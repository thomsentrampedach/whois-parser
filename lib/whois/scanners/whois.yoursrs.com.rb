require_relative 'base'

module Whois
  module Scanners

    class WhoisYoursrsCom < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :scan_keyvalue,
          :skip_gdpr_message,
          :scan_disclaimer
      ]


      tokenizer :scan_available do
        if @input.scan(/^No match for [\w\.]+/)
          @ast["status:available"] = true
        end
      end

      tokenizer :skip_gdpr_message do
        @input.skip(/^Please email the listed admin.+\n?/)
      end

      tokenizer :scan_disclaimer do
        if @input.match?(/^The data in this whois database/)
          @ast["field:disclaimer"] = _scan_lines_to_array(/^(.+)\n/).join(" ")
        end
      end
    end

  end
end
