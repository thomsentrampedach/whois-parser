require_relative 'base_icann_compliant'
module Whois
  class Parsers
    class WhoisRegistreMa < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^Domain Status: No Object Found/
      # pattern_disclaimer: /^Access to/,
      # pattern_throttled: /^WHOIS LIMIT EXCEEDED/,
      }
    end
  end
end
