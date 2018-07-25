require_relative 'base_icann_compliant'
module Whois
  class Parsers
    class WhoisNicJobs < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^No match for/,
      # pattern_throttled: /^WHOIS LIMIT EXCEEDED/,
      }
    end
  end
end
