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

    # Parser for the whois.hkirc.hk server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisHkircHk < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        content_for_scanner.strip == 'The domain has not been registered.'
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Domain Name Commencement Date:\s(.+?)\n/
          parse_time($1)
        end
      end

      property_not_supported :updated_on

      property_supported :expires_on do
        if content_for_scanner =~ /Expiry Date:\s(.+?)\n/
          parse_time($1.strip)
        end
      end


      property_supported :nameservers do
        if content_for_scanner =~ /Name Servers Information:\n\n((.+\n)+)\n/
          $1.split("\n").map do |name|
            Parser::Nameserver.new(:name => name.strip.downcase)
          end
        end
      end

      property_supported :registrant_contacts do
        build_contact('Registrant', Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact('Administrative', Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact('Technical', Parser::Contact::TYPE_TECHNICAL)
      end

      property_supported :registrar do
        Parser::Registrar.new({
            name:         node("Registrar Name"),
            organization: "HKIRC-Accredited Registrars",
            url:          'https://www.hkirc.hk',
            email:        node("Email", node("Registrar Contact Information")),
            phone:        node("Phone number", node("Registrar Contact Information"))
        })
      end

      private

      def node(match, content=content_for_scanner)
        content[/#{match}:\s*(.+)\s*$/, 1]
      end

      def build_contact(element, type)
        if content_for_scanner =~ /#{element} Contact Information:\n\n((.+\n)+)\n/
          Parser::Contact.new(
            type:         type,
            name:         contact_name($1),
            address:      node('Address', $1),
            country_code: node('Country', $1),
            phone:        node('Phone', $1),
            fax:          node('Fax', $1),
            email:        node('Email', $1)
          )
        end
      end

      def contact_name(content)
        node('Company English Name (It should be the same as the registered/corporation name on your Business Register Certificate or relevant documents)', content) || "#{node('Given name', content)} #{node('Family name', content)}".strip
      end
    end

  end
end
