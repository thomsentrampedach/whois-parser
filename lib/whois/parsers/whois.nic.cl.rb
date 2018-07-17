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
    # = whois.nic.cl parser
    #
    # Parser for the whois.nic.cl server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisNicCl < Base

      property_supported :domain do
        if content_for_scanner =~ /Domain name:\s(.+?)\n/
          $1
        end
      end

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
         !!(content_for_scanner =~ /^(.+?): no entries found.$/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Creation date:\s(.+?)\n/
          parse_time($1)
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Expiration date:\s+(.+?)\n/
          parse_time($1)
        end
      end

      property_not_supported :updated_on

      property_supported :nameservers do
        content_for_scanner.scan(/Name server:\s(.+?)\n/).flatten.map do |line|
          name, ipv4 = line.split(/\s+/)
          Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
        end
      end

      property_supported :registrant_contacts do
        content_for_scanner =~ /Registrant name:\s+(.+?)\n/
        name = $1
        content_for_scanner =~ /Registrant organisation:\s+(.+?)\n/
        org = $1

        Parser::Contact.new(
          :type         => Parser::Contact::TYPE_REGISTRANT,
          :id           => nil,
          :name         => name,
          :organization => org,
          :address      => nil,
          :city         => nil,
          :zip          => nil,
          :state        => nil,
          :country      => nil,
          :phone        => nil,
          :fax          => nil,
          :email        => nil
        )
      end

      property_not_supported :admin_contacts
      property_not_supported :technical_contacts

      property_supported :registrar do
        content_for_scanner =~ /Registrar name:\s+(.+?)\n/
        name = $1
        content_for_scanner =~ /Registrar URL:\s+(.+?)\n/
        url = $1

        Parser::Registrar.new({
            id:           nil,
            name:         name,
            url:          url
        })
      end

    end

  end
end
