#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icann_compliant'

module Whois
  class Parsers

    # Parser for the whois.pir.org server.
    class WhoisPirOrg < BaseIcannCompliant

      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^NOT FOUND\n/,
          pattern_disclaimer: /^Access to/,
          pattern_throttled: /^WHOIS LIMIT EXCEEDED/,
      }

      property_supported :disclaimer do
        node("field:disclaimer")
      end

      property_supported :registrar do
        return unless node("Registrar")
        Parser::Registrar.new({
            id:           node("Registrar IANA ID"),
            name:         node("Registrar"),
            organization: node("Registrar"),
            url:          node("Registrar URL"),
            email:        node("Registrar Abuse Contact Email"),
            phone:        node("Registrar Abuse Contact Phone")
        })
      end

      # Checks whether the response has been throttled.
      #
      # @return [Boolean]
      #
      # @example
      #   WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS
      #
      def response_throttled?
        !!node("response:throttled")
      end

    end

  end
end
