module Facter::Util::IP
  module Macaddress

    MAP = {
      :linux => {
        :ip => {
          :regex => '((\w{1,2}:){5,}\w{1,2})',
          :exec  => '/sbin/ip addr show',
          :token => '(?:ether|HWaddr)\s',
        },
        :ifconfig => {
          :regex  => '((\w{1,2}:){5,}\w{1,2})',
          :exec   => '/sbin/ifconfig',
          :token  => '(?:ether|HWaddr)\s',
        },
      },
      :bsdlike => {
        :aliases  => [:openbsd, :netbsd, :freebsd, :darwin, :"gnu/kfreebsd", :dragonfly],
        :ifconfig => {
          :regex  => '((\w{1,2}:){5,}\w{1,2})',
          :exec  => '/sbin/ifconfig',
          :token => '(?:ether|HWaddr)\s',
        },
      },
      :sunos => {
        :ifconfig => {
          :regex  => '(\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}$)',
          :exec  => '/usr/bin/netstat -np',
          :token => 'SPLA\s+',
        },
      },
      :"hp-ux" => {
        :ifconfig => {
          :regex  => '(0x\w+)',
          :exec  => '/usr/sbin/lanscan',
          :token => '[\d{1,2}\/]+\s+',
        },
      },
      :aix => {
        :ifconfig => {
          :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
          :exec  => '/sbin/ifconfig -a',
          :token => 'inet ',
        },
      },
      :windows => {
        :netsh => {
          :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
          :exec  => "#{ENV['SYSTEMROOT']}/system32/netsh.exe interface ip show interface",
          :token => 'IP Address:\s+',
        },
      },
    }

    def self.get(interface, ignore=nil)
      return nil unless Facter::Util::IP.supported_platforms(MAP)

      macaddress = nil
      map = Facter::Util::IP.find_submap(MAP)

      # This checks each exec in turn until one is found and then uses that
      # method for the rest of the matches.
      method = Facter::Util::IP.find_method(map)
      exec   = map[method.to_sym][:exec]
      token  = map[method.to_sym][:token]
      regex  = map[method.to_sym][:regex]
      if ignore.nil?
        ignore = map[method.to_sym][:ignore]
      end


      command = "#{exec}"
      command << " #{interface}" unless interface.nil?

      output = Facter::Util::Resolution.exec(command)
      return [] if output.nil?
      macaddress = Facter::Util::IP.find_token(output, token, regex, ignore)

      self.standardize(macaddress)
    end

    def self.standardize(macaddress)
      return nil unless macaddress

      # For HP-UX we have to do special things
      if Facter.value(:kernel).downcase.to_sym == :"hp-ux"
        macaddress.sub(/0x(\S+)/,'\1').scan(/../).join(":")
      else
        macaddress.split(":").map{|x| "0#{x}"[-2..-1]}.join(":")
      end
    end

  end
end
