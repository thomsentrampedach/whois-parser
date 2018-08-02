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

    # Parser for the kero.yachay.pe server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class KeroYachayPe < Base

      property_supported :status do
        if content_for_scanner =~ /Domain Status:\s+(.+?)\n/
          case $1.downcase
          when "no object found"
            :available
          else
            :registered
          end
        else
          Whois::Parser.bug!(ParserError, "Unable to parse status.")
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        !available?
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_supported :nameservers do
        content_for_scanner.scan(/Name Server:\s*(.+?)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name.strip)
        end
      end

      property_supported :admin_contacts do
        Parser::Contact.new(
          type:         Parser::Contact::TYPE_ADMINISTRATIVE,
          name:         content_for_scanner[/Admin Name:\s+(.+)\n/, 1],
          email:        content_for_scanner[/Admin Email:\s+(.+)\n/, 1]
        )
      end

      property_not_supported :registrant_contacts
      property_not_supported :technical_contacts
      property_not_supported :registrar

      # Checks whether the response has been throttled.
      #
      # @return [Boolean]
      #
      # @example
      #   Looup quota exceeded.
      #
      def response_throttled?
        !content_for_scanner.match(/Looup quota exceeded./).nil?
      end

    end

  end
end
