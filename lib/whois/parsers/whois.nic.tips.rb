require_relative 'base_icann_compliant'

module Whois
  class Parsers

    class WhoisNicTips < BaseIcannCompliant
      property_supported :expires_on do
        node("Registry Expiry Date") do |value|
          parse_time(value)
        end
      end
    end
  end
end
