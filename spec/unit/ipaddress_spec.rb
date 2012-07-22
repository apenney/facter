#! /usr/bin/env ruby -S rspec

require 'spec_helper'

describe "ipaddress fact" do

  describe "on linux" do
    before do
      Facter.fact(:kernel).stubs(:value).returns("Linux")
    end

    it "should return ipddress for linux" do
      Facter::Util::IP.stubs(:ipaddress).with(nil).returns("131.252.209.153")
      Facter.fact(:ipaddress).value.should == "131.252.209.153"
    end
  end

  describe "on FreeBSD" do
    before do
      Facter.fact(:kernel).stubs(:value).returns("FreeBSD")
    end

    it "should return ipddress for freebsd" do
      Facter::Util::IP.stubs(:ipaddress).with(nil).returns("131.252.209.153")
      Facter.fact(:ipaddress).value.should == "131.252.209.153"
    end
  end

end
