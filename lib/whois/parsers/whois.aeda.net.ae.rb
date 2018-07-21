#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'


module Whois
  class Parsers

    # Parser for the whois.aeda.net.ae server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisAedaNetAe < Base

      property_supported :status do
        if content_for_scanner =~ /Status:\s+(.+?)\n/
          case $1.downcase
            when "ok" then :registered
            else
              Whois::Parser.bug!(ParserError, "Unknown status `#{$1}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        content_for_scanner.strip == "No Data Found"
      end

      property_supported :registered? do
        !available?
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_supported :nameservers do
        content_for_scanner.scan(/Name Server:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end

      property_supported :registrar do
        Parser::Registrar.new({
            id:   node("Registrar ID"),
            name: node("Registrar Name"),
        })
      end

      property_supported :registrant_contacts do
        build_contact('Registrant Contact', Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact('Admin Contact', Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact('Tech Contact', Parser::Contact::TYPE_TECHNICAL)
      end

      private

      def node(match)
        content_for_scanner[/#{match}:\s*(.+)\s*$/, 1]
      end

      def build_contact(element, type)
        Parser::Contact.new(
            type:         type,
            id:           node("#{element} ID"),
            name:         node("#{element} Name"),
            email:        node("#{element} Email")
        )
      end
    end

  end
end
