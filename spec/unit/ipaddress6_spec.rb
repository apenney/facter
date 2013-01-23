#! /usr/bin/env ruby

require 'spec_helper'
require 'facter/util/ip'

def ifconfig_fixture(filename)
  File.read(fixtures('ifconfig', filename))
end

def netsh_fixture(filename)
  File.read(fixtures('netsh', filename))
end


describe "IPv6 address fact" do
  include FacterSpec::ConfigHelper

  before do
    given_a_configuration_of(:is_windows => false)
  end

  [:freebsd, :linux, :openbsd, :darwin, :"hp-ux", :"gnu/kfreebsd", :windows].each do |platform|
    it "should return ipddress for #{platform}" do
      Facter.fact(:kernel).stubs(:value).returns(platform)
      Facter::Util::IP.stubs(:get_attribute).with(nil, attribute='ipaddress', subtype='ipv6').returns("2610:10:20:209:223:32ff:fed5:ee34")
      Facter.fact(:ipaddress6).value.should == "2610:10:20:209:223:32ff:fed5:ee34"
    end
  end

  [:netbsd, :sunos].each do |platform|
    it "should return ipddress for #{platform}" do
      Facter.fact(:kernel).stubs(:value).returns(platform)
      Facter::Util::IP.stubs(:get_attribute).with(nil, attribute='ipaddress', subtype='ipv6', ignore=/^127\.|^0\.0\.0\.0/).returns("2610:10:20:209:223:32ff:fed5:ee34")
      Facter.fact(:ipaddress6).value.should == "2610:10:20:209:223:32ff:fed5:ee34"
    end
  end

end
