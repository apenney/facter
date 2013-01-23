#! /usr/bin/env ruby

require 'spec_helper'
require 'facter/util/ip'

describe "ipaddress fact" do
  [:freebsd, :linux, :openbsd, :darwin, :"hp-ux", :"gnu/kfreebsd", :windows].each do |platform|
    it "should return ipddress for #{platform}" do
      Facter.fact(:kernel).stubs(:value).returns(platform)
      Facter::Util::IP.stubs(:get_attribute).with(nil, 'ipaddress', 'ipv4').returns("131.252.209.153")
      Facter.fact(:ipaddress).value.should == "131.252.209.153"
    end
  end

  [:netbsd, :sunos].each do |platform|
    it "should return ipddress for #{platform}" do
      Facter.fact(:kernel).stubs(:value).returns(platform)
      Facter::Util::IP.stubs(:get_attribute).with(nil, 'ipaddress', 'ipv4', /^127\.|^0\.0\.0\.0/).returns("131.252.209.153")
      Facter.fact(:ipaddress).value.should == "131.252.209.153"
    end
  end

end
