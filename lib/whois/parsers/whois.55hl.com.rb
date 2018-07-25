require_relative 'base_icann_compliant'
module Whois
  class Parsers
    class Whois55hlCom < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^no match for/
      # pattern_disclaimer: /^Access to/,
      # pattern_throttled: /^WHOIS LIMIT EXCEEDED/,
      }
    end
  end
end
