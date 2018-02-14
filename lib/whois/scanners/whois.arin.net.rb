require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.arin.net record.
    class WhoisArinNet < Base

      self.tokenizers += [
        :skip_empty_line,
        :scan_disclaimer,
        :skip_comment,
        :scan_keyvalue,
      ]

      tokenizer :scan_disclaimer do
        if @ast["field:disclaimer"].nil?
          @input.skip_until(/ARIN WHOIS data and services are subject/m)
          @ast["field:disclaimer"] = ('ARIN WHOIS data and services are subject' << @input.scan_until(/^$/)).gsub(/#\s?/, '')
        end
      end

      tokenizer :skip_comment do
        @input.skip(/^#.*\n/)
      end
    end
  end
end
