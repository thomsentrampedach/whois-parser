require_relative 'base_icann_compliant'
module Whois
  class Parsers
    class WhoisNicIcu < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /DOMAIN NOT FOUND/
      # pattern_disclaimer: /^Access to/,
      # pattern_throttled: /^WHOIS LIMIT EXCEEDED/,
      }
    end
  end
end
