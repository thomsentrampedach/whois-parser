#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/base_cocca2.rb'


module Whois
  class Parsers

    # Base parser for CoCCA servers.
    #
    # @abstract
    class BaseCocca2 < Base
      include Scanners::Scannable

      self.scanner = Scanners::BaseCocca2


      property_supported :domain do
        node("Domain Name")
      end

      property_supported :domain_id do
        node("Domain ID")
      end


      # TODO: /pending delete/ => :redemption
      # TODO: /pending purge/  => :redemption
      property_supported :status do
        list = Array.wrap(node("Domain Status")).map(&:downcase)
        case
        when list.include?("no object found")
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("Creation Date") { |value| parse_time(value) }
      end

      property_supported :updated_on do
        node("Updated Date") { |value| parse_time(value) }
      end

      property_supported :expires_on do
        node("Registry Expiry Date") { |value| parse_time(value) }
      end

      property_supported :registrar do
        if name = node("Registrar").presence || node("Sponsoring Registrar").presence
          Parser::Registrar.new(
            id:    node('Sponsoring Registrar IANA ID').presence,
            name:  name,
            url:   node('Registrar URL').presence || node('Sponsoring Registrar URL').presence,
            email: node('Registrar Abuse Email'),
            phone: node('Registrar Abuse Phone')
          )
        end
      end

      property_supported :registrant_contacts do
        build_contact('Registrant', Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact('Admin', Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact('Tech', Parser::Contact::TYPE_TECHNICAL)
      end

      property_supported :nameservers do
        Array.wrap(node("Name Server")).map do |name|
          Parser::Nameserver.new(name: name)
        end
      end

      protected

      def build_contact(element, type)
        node("#{element} Name") do
          Parser::Contact.new(
              type:         type,
              id:           node("#{element} ID").presence,
              name:         node("#{element} Name"),
              organization: node("#{element} Organization"),
              address:      node("#{element} Street"),
              city:         node("#{element} City"),
              zip:          node("#{element} Postal Code"),
              state:        node("#{element} State/Province"),
              country_code: node("#{element} Country"),
              phone:        node("#{element} Phone"),
              fax:          node("#{element} Fax"),
              email:        node("#{element} Email")
          )
        end
      end
    end
  end
end
