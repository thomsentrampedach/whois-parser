require_relative 'base_icann_compliant'
module Whois
  class Parsers
    class WhoisYoursrsCom < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^Domain not found|^Invalid domain name|^No match for/
      # pattern_disclaimer: /^Access to/,
      # pattern_throttled: /^WHOIS LIMIT EXCEEDED/,
      }
    end
  end
end
