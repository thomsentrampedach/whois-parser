require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.dns.hr record.
    class WhoisDnsHr < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :scan_disclaimer,
          :scan_keyvalue,
      ]


      tokenizer :scan_available do
        if @input.skip(/^%ERROR: no entries found\n/)
          @ast["status:available"] = true
        end
      end

      tokenizer :scan_disclaimer do
        if @input.match?(/^%/)
          @ast["field:disclaimer"] = _scan_lines_to_array(/%(.*)\n/).map(&:strip).join("\n")
        end
      end

    end

  end
end
