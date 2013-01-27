# Fact: macaddress
#
# Purpose:
#
# Resolution:
#
# Caveats:
#

require 'facter/util/macaddress'

Facter.add(:macaddress) do
  confine :kernel => 'Linux'
  has_weight  10                # about an order of magnitude faster
  setcode do
    begin
      Dir.glob('/sys/class/net/*').reject {|x| x[-3..-1] == '/lo' }.first
      path and File.read(path + '/address')
    rescue Exception
      nil
    end
  end
end

Facter.add(:macaddress) do
  confine :kernel => [:linux, :sunos, :"gnu/kfreebsd", :freebsd, :openbsd, :dragonfly, :darwin, :aix, :windows]
  setcode do
    Facter::Util::IP::Macaddress.get(nil)
    end
  end
end
