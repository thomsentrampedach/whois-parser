require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.arin.net record.
    class WhoisRipeNet < Base

      self.tokenizers += [
        :skip_empty_line,
        :scan_disclaimer,
        :scan_abuse_email,
        :skip_comment,
        :scan_keyvalue,
      ]

      tokenizer :scan_disclaimer do
        if @ast["field:disclaimer"].nil?
          @input.skip_until(/The RIPE Database is subject/m)
          @ast["field:disclaimer"] = ('The RIPE Database is subject' << @input.scan_until(/^$/)).gsub(/%\s?/, '')
        end
      end

      tokenizer :scan_abuse_email do
        if @ast['field:abuse_email'].nil?
          @input.skip_until(/% Abuse contact for '[\.\d]* - [\.\d]*' is '/m)
          @ast['field:abuse_email'] = @input[1] if @input.scan(/(.+?)'$/)
        end
      end

      tokenizer :skip_empty_line do
        if @input.skip(/^\n/)
          @block_id = nil
          true
        end
      end

      tokenizer :skip_comment do
        @input.skip(/^%.*\n/)
      end

      # Scan a key/value pair and stores the result in the current target.
      # target is the global @ast if no '_section' is set, else '_section' is used.
      tokenizer :scan_keyvalue do
        if @input.scan(/(.+?):(.*?)(\n|\z)/)
          key, value = @input[1].strip, @input[2].strip

          @block_id ||= key
          key = "#{@block_id}:#{key}"

          target = @tmp['_section'] ? (@ast[@tmp['_section']] ||= {}) : @ast

          if target[key].nil?
            target[key] = value
          else
            target[key] = Array.wrap(target[key])
            target[key] << value
          end
        end
      end

      tokenizer :skip_provider_aggregated_block do
        @input.skip(/^[\s]*Provider Aggregated Block\n/)
      end
    end
  end
end
