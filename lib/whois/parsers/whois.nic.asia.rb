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

    # Parser for the whois.nic.asia server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicAsia < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^NOT FOUND\n/,
          pattern_disclaimer: /^Access to/
      }

      property_supported :disclaimer do
        node("field:disclaimer")
      end

      property_supported :status do
        if reserved?
          :reserved
        else
          super()
        end
      end

      # NEWPROPERTY
      def reserved?
        !!content_for_scanner.match(/^Reserved by DotAsia\n/)
      end
    end

  end
end
