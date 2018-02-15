require_relative 'base_icann_compliant'

module Whois
  class Parsers

    # Parser for the whois.nic.cloud server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicCloud < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^No Data Found\n/
      }

      property_supported :expires_on do
        node("Registry Expiry Date") do |value|
          parse_time(value)
        end
      end
    end

  end
end
