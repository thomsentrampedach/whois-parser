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

    #
    # = whois.sk-nic.sk parser
    #
    # Parser for the whois.sk-nic.sk server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisSkNicSk < Base

      # == Values for Status
      #
      # @see https://www.sk-nic.sk/documents/stavy_domen.html
      # @see http://www.inwx.de/en/sk-domain.html
      #
      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^Not found/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if time = content_for_scanner.scan(/Created:\s+(.+)\n/).flatten.first
          parse_time(time)
        end
      end

      property_supported :updated_on do
        if time = content_for_scanner.scan(/Updated:\s+(.+)\n/).flatten.first
          parse_time(time)
        end
      end

      property_supported :expires_on do
        if time = content_for_scanner.scan(/Valid Until:\s+(.+)\n/).flatten.first
          parse_time(time)
        end
      end


      property_supported :nameservers do
        content_for_scanner.scan(/Nameserver:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end

      property_not_supported :registrar
      property_not_supported :technical_contacts
      property_not_supported :admin_contacts
      property_not_supported :registrant_contacts
    end
  end
end
