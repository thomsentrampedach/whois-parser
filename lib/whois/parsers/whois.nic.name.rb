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

    # Parser for the whois.nic.name server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicName < Base

      property_supported :status do
        content_for_scanner.scan(/Domain Status:\s+(.+?)\n/).flatten
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^No match/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Created On: (.+)\n/
          parse_time($1)
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /Updated On: (.+)\n/
          parse_time($1)
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Expires On: (.+)\n/
          parse_time($1)
        end
      end

      property_supported :nameservers do
        content_for_scanner.scan(/Name Server:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name.downcase)
        end
      end

      property_supported :registrar do
        Parser::Registrar.new({
          id:           content_for_scanner[/Registrar IANA ID:\s+(.+)\n/, 1],
          name:         content_for_scanner[/Registrar:\s+(.+)\n/, 1],
          organization: content_for_scanner[/Registrar:\s+(.+)\n/, 1],
          email:        content_for_scanner[/Registrar Abuse Contact Email:\s+(.+)\n/, 1],
          phone:        content_for_scanner[/Registrar Abuse Contact Phone:\s+(.+)\n/, 1],
        })
      end

      property_not_supported :registrant_contacts
      property_not_supported :admin_contacts
      property_not_supported :technical_contacts
    end
  end
end
