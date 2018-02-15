# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.launchpad.com/com/status_registered.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/whois.launchpad.com.rb'

describe Whois::Parsers::WhoisLaunchpadCom, "status_registered.expected" do

  subject do
    file = fixture("responses", "whois.launchpad.com/com/status_registered.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#domain" do
    it do
      expect(subject.domain).to eq("jouzik.com")
    end
  end
  describe "#domain_id" do
    it do
      expect(subject.domain_id).to eq("1853653287_DOMAIN_COM-VRSN")
    end
  end
  describe "#status" do
    it do
      expect(subject.status).to eq(:registered)
    end
  end
  describe "#available?" do
    it do
      expect(subject.available?).to eq(false)
    end
  end
  describe "#registered?" do
    it do
      expect(subject.registered?).to eq(true)
    end
  end
  describe "#created_on" do
    it do
      expect(subject.created_on).to be_a(Time)
      expect(subject.created_on).to eq(Time.parse("2014-04-07T01:59:11Z"))
    end
  end
  describe "#updated_on" do
    it do
      expect(subject.updated_on).to be_a(Time)
      expect(subject.updated_on).to eq(Time.parse("2017-04-03T21:21:03Z"))
    end
  end
  describe "#expires_on" do
    it do
      expect(subject.expires_on).to be_a(Time)
      expect(subject.expires_on).to eq(Time.parse("2018-04-07T01:59:11Z"))
    end
  end
  describe "#registrar" do
    it do
      expect(subject.registrar).to be_a(Whois::Parser::Registrar)
      expect(subject.registrar.id).to eq("955")
      expect(subject.registrar.name).to eq("Launchpad, Inc. (HostGator)")
    end
  end
  describe "#registrant_contacts" do
    it do
      expect(subject.registrant_contacts).to be_a(Array)
      expect(subject.registrant_contacts.size).to eq(1)
      expect(subject.registrant_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.registrant_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_REGISTRANT)
      expect(subject.registrant_contacts[0].id).to eq("Not Available From Registry")
      expect(subject.registrant_contacts[0].name).to eq("Domain Admin")
      expect(subject.registrant_contacts[0].organization).to eq("Privacy Protect, LLC (PrivacyProtect.org)")
      expect(subject.registrant_contacts[0].address).to eq("10 Corporate Drive")
      expect(subject.registrant_contacts[0].city).to eq("Burlington")
      expect(subject.registrant_contacts[0].zip).to eq("01803")
      expect(subject.registrant_contacts[0].state).to eq("MA")
      expect(subject.registrant_contacts[0].country).to eq(nil)
      expect(subject.registrant_contacts[0].country_code).to eq("US")
      expect(subject.registrant_contacts[0].phone).to eq("+1.8022274003")
      expect(subject.registrant_contacts[0].email).to eq("contact@privacyprotect.org")
    end
  end
  describe "#admin_contacts" do
    it do
      expect(subject.admin_contacts).to be_a(Array)
      expect(subject.admin_contacts.size).to eq(1)
      expect(subject.admin_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.admin_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_ADMINISTRATIVE)
      expect(subject.admin_contacts[0].id).to eq("Not Available From Registry")
      expect(subject.admin_contacts[0].name).to eq("Domain Admin")
      expect(subject.admin_contacts[0].organization).to eq("Privacy Protect, LLC (PrivacyProtect.org)")
      expect(subject.admin_contacts[0].address).to eq("10 Corporate Drive")
      expect(subject.admin_contacts[0].city).to eq("Burlington")
      expect(subject.admin_contacts[0].zip).to eq("01803")
      expect(subject.admin_contacts[0].state).to eq("MA")
      expect(subject.admin_contacts[0].country).to eq(nil)
      expect(subject.admin_contacts[0].country_code).to eq("US")
      expect(subject.admin_contacts[0].phone).to eq("+1.8022274003")
      expect(subject.admin_contacts[0].email).to eq("contact@privacyprotect.org")
    end
  end
  describe "#technical_contacts" do
    it do
      expect(subject.technical_contacts).to be_a(Array)
      expect(subject.technical_contacts.size).to eq(1)
      expect(subject.technical_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.technical_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_TECHNICAL)
      expect(subject.technical_contacts[0].id).to eq("Not Available From Registry")
      expect(subject.technical_contacts[0].name).to eq("Domain Admin")
      expect(subject.technical_contacts[0].organization).to eq("Privacy Protect, LLC (PrivacyProtect.org)")
      expect(subject.technical_contacts[0].address).to eq("10 Corporate Drive")
      expect(subject.technical_contacts[0].city).to eq("Burlington")
      expect(subject.technical_contacts[0].zip).to eq("01803")
      expect(subject.technical_contacts[0].state).to eq("MA")
      expect(subject.technical_contacts[0].country).to eq(nil)
      expect(subject.technical_contacts[0].country_code).to eq("US")
      expect(subject.technical_contacts[0].phone).to eq("+1.8022274003")
      expect(subject.technical_contacts[0].email).to eq("contact@privacyprotect.org")
    end
  end
  describe "#nameservers" do
    it do
      expect(subject.nameservers).to be_a(Array)
      expect(subject.nameservers.size).to eq(2)
      expect(subject.nameservers[0]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[0].name).to eq("cns2013.hostgator.com")
      expect(subject.nameservers[1]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[1].name).to eq("cns2014.hostgator.com")
    end
  end
end