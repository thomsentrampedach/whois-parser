require_relative 'base'

module Whois
  class Parsers
    class WhoisId < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /DOMAIN NOT FOUND/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Created On:\s*(.*)\n/
          parse_time($1)
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /Last Updated On:\s*(.*)\n/
          parse_time($1)
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Expiration Date:\s*(.*)\n/
          parse_time($1)
        end
      end

      property_supported :nameservers do
        content_for_scanner.scan(/Name Server:\s*(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name.chomp("."))
        end
      end

      property_not_supported :registrant_contacts
      property_not_supported :admin_contacts
      property_not_supported :technical_contacts
      property_not_supported :registrar
    end
  end
end
