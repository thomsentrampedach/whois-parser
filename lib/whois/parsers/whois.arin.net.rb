require_relative 'base'
require 'whois/scanners/whois.arin.net'

module Whois
  class Parsers

    # Parser for the whois.antagus.de server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisArinNet < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisArinNet

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :created_on do
        node("RegDate") do |value|
          if value.is_a?(Array)
            parse_time(value.last)
          else
            parse_time(value)
          end
        end
      end

      property_supported :updated_on do
        node("Updated") do |value|
          if value.is_a?(Array)
            parse_time(value.last)
          else
            parse_time(value)
          end
        end
      end

      # TODO not sure about this
      property_supported :registered? do
        node("RegDate") do |value|
          value.to_s.strip != ''
        end
      end

      property_supported :available? do
         !registered?
      end

      property_supported :registrant_contacts do
        build_contact('NOC', Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact('Abuse', Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact('Tech', Parser::Contact::TYPE_TECHNICAL)
      end

      property_not_supported :expires_on
      property_not_supported :nameservers

      # TODO not sure about this
      def response_throttled?
        node("Organization") do |value|
          value.to_s.strip == ''
        end
      end

      protected

      # "OrgNOCHandle"=>"AANO1-ARIN",
      # "OrgNOCName"=>"Amazon AWS Network Operations",
      # "OrgNOCPhone"=>"+1-206-266-4064",
      # "OrgNOCEmail"=>"amzn-noc-contact@amazon.com",
      # "OrgNOCRef"=>"https://whois.arin.net/rest/poc/AANO1-ARIN",
      def build_contact(element, type)
        Parser::Contact.new(
          type:         type,
          name:         value_for_property(element, 'Name'),
          organization: node('OrgName'),
          address:      node('Address'),
          city:         node('City'),
          zip:          node('PostalCode'),
          state:        node('StateProv'),
          country_code: node('Country'),
          phone:        value_for_property(element, 'Phone'),
          email:        value_for_property(element, 'Email')
        )
      end

      private

      def value_for_phone_property(element, property)
        [
          value_for_property(element, "#{property}"),
          value_for_property(element, "#{property} Ext")
        ].reject(&:empty?).join(' ext: ')
      end

      def value_for_property(element, property)
        Array.wrap(node("Org#{element}#{property}")).reject(&:empty?).join(', ')
      end
    end
  end
end
