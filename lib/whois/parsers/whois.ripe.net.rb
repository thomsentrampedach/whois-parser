#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.ripe.net'

module Whois
  class Parsers

    #
    # = whois.ripe.net parser
    #
    # Parser for the whois.ripe.net server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisRipeNet < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisRipeNet

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /%ERROR:101: no entries found/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("inetnum:created") do |value|
          if value.is_a?(Array)
            parse_time(value.last)
          else
            parse_time(value)
          end
        end
      end

      property_supported :updated_on do
        node("inetnum:last-modified") do |value|
          if value.is_a?(Array)
            parse_time(value.last)
          else
            parse_time(value)
          end
        end
      end

      property_not_supported :expires_on
      property_not_supported :registrar

      # Nameservers are listed in the following formats:
      #
      #   nserver:      ns.nic.mc
      #   nserver:      ns.nic.mc 195.78.6.131
      #
      property_supported :nameservers do
        content_for_scanner.scan(/nserver:\s+(.+)\n/).flatten.map do |line|
          name, ipv4 = line.split(/\s+/)
          name = [name].flatten.map(&:downcase).join(',')
          Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
        end
      end

      property_supported :registrant_contacts do
        build_contact('organisation:abuse-c', Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact('inetnum:admin-c', Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact('inetnum:tech-c', Parser::Contact::TYPE_TECHNICAL)
      end

      # TODO not sure about this
      def response_throttled?
        node("inetnum:inetnum") do |value|
          value.to_s.strip == ''
        end
      end

      protected

      # "OrgNOCHandle"=>"AANO1-ARIN",
      # "OrgNOCName"=>"Amazon AWS Network Operations",
      # "OrgNOCPhone"=>"+1-206-266-4064",
      # "OrgNOCEmail"=>"amzn-noc-contact@amazon.com",
      # "OrgNOCRef"=>"https://whois.arin.net/rest/poc/AANO1-ARIN",
      def build_contact(element, type)
        block_id = node(element) do |contact_id|
          pair = @ast.find do |k, v|
            k.match?(/nic-hdl/) && v && v.downcase == contact_id.downcase
          end

          pair.first.split(':').first if pair && pair.first
        end

        Parser::Contact.new(
          type:         type,
          name:         node("#{block_id}:#{block_id}"),
          organization: node("#{block_id}:org-name"),
          address:      value_for_property(block_id, 'address'),
          country_code: node('inetnum:country'),
          phone:        node("#{block_id}:phone"),
          fax:          node("#{block_id}:fax-no"),
          email:        node('field:abuse_email')
        )
      end

      private

      def value_for_property(block_id, property)
        Array.wrap(node("#{block_id}:#{property}")).reject(&:empty?).join(', ')
      end
    end
  end
end
