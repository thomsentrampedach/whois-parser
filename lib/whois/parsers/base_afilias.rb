#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/base_afilias'


module Whois
  class Parsers

    # Base parser for Afilias servers.
    #
    # @abstract
    class BaseAfilias < Base
      include Scanners::Scannable

      self.scanner = Scanners::BaseAfilias


      property_supported :disclaimer do
        node("field:disclaimer")
      end


      property_supported :domain do
        node("Domain Name", &:downcase)
      end

      property_supported :domain_id do
        node(["Domain ID", "Registry Domain ID"])
      end


      property_supported :status do
        if node?("Status")
          Array.wrap(node("Status"))
        elsif available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!node("status:available")
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node(["Created On", "Creation Date"]) do |value|
          parse_time(value)
        end
      end

      property_supported :updated_on do
        node(["Last Updated On", "Updated Date"]) do |value|
          parse_time(value)
        end
      end

      property_supported :expires_on do
        node(["Expiration Date", "Registry Expiry Date"]) do |value|
          parse_time(value)
        end
      end


      property_supported :registrar do
        if node?("Sponsoring Registrar")
          node("Sponsoring Registrar") do |value|
            id, name = decompose_registrar(value) ||
                Whois::Parser.bug!(ParserError, "Unknown registrar format `#{value}'")

            Parser::Registrar.new(
                id:           id,
                name:         name
            )
          end
        elsif node?("Registrar")
          Parser::Registrar.new({
            id:           node("Registrar IANA ID"),
            name:         node("Registrar"),
            organization: node("Registrar"),
            url:          node("Registrar URL"),
            email:        node("Registrar Abuse Contact Email"),
            phone:        node("Registrar Abuse Contact Phone")
          })
        end
      end

      property_supported :registrant_contacts do
        build_contact("Registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Admin", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("Tech", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        Array.wrap(node("Name Server")).reject(&:empty?).map do |name|
          Parser::Nameserver.new(:name => name.downcase)
        end
      end


      private

      def build_contact(element, type)
        if node?("#{element} ID")
          node("#{element} ID") do
            address = ["", "1", "2", "3"].
                map { |i| node("#{element} Street#{i}") }.
                delete_if { |i| i.nil? || i.empty? }.
                join("\n")

            Parser::Contact.new(
                :type         => type,
                :id           => node("#{element} ID"),
                :name         => node("#{element} Name"),
                :organization => node("#{element} Organization"),
                :address      => address,
                :city         => node("#{element} City"),
                :zip          => node("#{element} Postal Code"),
                :state        => node("#{element} State/Province"),
                :country_code => node("#{element} Country"),
                :phone        => node("#{element} Phone"),
                :fax          => node("#{element} FAX") || node("#{element} Fax"),
                :email        => node("#{element} Email")
            )
          end
        elsif node?("#{element} Name")
          node("#{element} Name") do
            Parser::Contact.new(
                type:         type,
                id:           node("Registry #{element} ID").presence,
                name:         value_for_property(element, 'Name'),
                organization: contact_organization_attribute(element),
                address:      contact_address_attribute(element),
                city:         value_for_property(element, 'City'),
                zip:          value_for_property(element, 'Postal Code'),
                state:        value_for_property(element, 'State/Province'),
                country_code: value_for_property(element, 'Country'),
                phone:        value_for_phone_property(element, 'Phone'),
                fax:          value_for_phone_property(element, 'Fax'),
                email:        value_for_property(element, 'Email')
            )
          end
        end
      end

      def decompose_registrar(value)
        if value =~ /(.+?) \((.+?)\)/
          [$2, $1]
        end
      end

      def contact_organization_attribute(element)
        value_for_property(element, 'Organization')
      end

      def contact_address_attribute(element)
        value_for_property(element, 'Street')
      end

      def value_for_phone_property(element, property)
        [
          value_for_property(element, "#{property}"),
          value_for_property(element, "#{property} Ext")
        ].reject(&:empty?).join(' ext: ')
      end

      def value_for_property(element, property)
        Array.wrap(node("#{element} #{property}")).reject(&:empty?).join(', ')
      end

    end

  end
end
