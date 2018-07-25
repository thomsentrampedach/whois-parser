require_relative 'base_icann_compliant'
module Whois
  class Parsers
    class Whois101domainCom < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^Invalid domain name/
      # pattern_disclaimer: /^Access to/,
      # pattern_throttled: /^WHOIS LIMIT EXCEEDED/,
      }
    end
  end
end
