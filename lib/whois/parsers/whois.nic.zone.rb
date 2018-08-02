require_relative 'base_icann_compliant'
module Whois
  class Parsers
    class WhoisNicZone < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^Domain not found/
      # pattern_disclaimer: /^Access to/,
      # pattern_throttled: /^WHOIS LIMIT EXCEEDED/,
      }
    end
  end
end
