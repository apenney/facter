# A base module for collecting IP-related
# information from all kinds of platforms.
module Facter::Util::IP

  REGEX_MAP = {
    :linux => {
      :netmask  => /Mask:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/
    },
    :bsd   => {
      :aliases  => [:openbsd, :netbsd, :freebsd, :darwin, :"gnu/kfreebsd", :dragonfly],
      :netmask  => /netmask\s+0x(\w{8})/
    },
    :sunos => {
      :netmask  => /netmask\s+(\w{8})/
    },
    :"hp-ux" => {
      :netmask  => /.*\s+netmask (\S+)\s.*/
    },
    :windows => {
      :netmask  => /\s+Subnet Prefix:\s+\S+\s+\(mask ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)/
    }
  }

  INTERFACE_MAP = {
    :linux => {
      :methods => {
        :ipaddress => {
          :ipv4 => {
            :ip => {
              :regex => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :exec  => '/sbin/ip addr show',
              :token => 'inet ',
            },
            :ifconfig => {
              :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :exec   => '/sbin/ifconfig',
              :token  => 'inet addr: ',
            },
          },
          :ipv6 => {
            :ip => {
              :regex => '((?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4})',
              :exec  => '/sbin/ip addr show',
              :token => 'inet6 ',
            },
            :ifconfig => {
              :regex  => '((?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4})',
              :exec   => '/sbin/ifconfig',
              :token  => 'inet6 addr: ',
            },
          },
        },
        :macaddress => {
          :ethernet => {
            :ip => {
              :exec  => '/sbin/ip addr show',
              :regex => '(\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2})',
              :token => 'link/ether ',
            },
            :ifconfig => {
              :exec   => '/sbin/ifconfig',
              :regex  => '(\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2})',
              :token  => '(?:ether|HWaddr) ',
            },
          },
        },
        :netmask => {
          :ipv4 => {
            :ip => {
              :exec  => '/sbin/ip addr show',
              :regex => '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/(\d+)',
              :token => 'inet ',
            },
            :ifconfig => {
              :exec   => '/sbin/ifconfig',
              :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :token  => 'Mask:',
            },
          },
          :ipv6 => {
            :ip => {
              :regex => '(?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4}\/(\d+)',
              :exec  => '/sbin/ip addr show',
              :token => 'inet6 ',
            },
            :ifconfig => {
              :regex  => '(?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4}\/(\d+)',
              :exec   => '/sbin/ifconfig',
              :token  => 'inet6 addr: ',
            },
          },
        },
      },
    },
    :bsdlike => {
      :aliases  => [:openbsd, :netbsd, :freebsd, :darwin, :"gnu/kfreebsd", :dragonfly],
      :methods => {
        :ipaddress => {
          :ipv4 => {
            :ifconfig => {
              :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :exec  => '/sbin/ifconfig',
              :token => 'inet addr: ',
            },
          },
          :ipv6 => {
            :ifconfig => {
              :regex => '((?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4})',
              :exec  => '/sbin/ifconfig',
              :token => 'inet6 addr: ',
            },
          },
        },
        :macaddress => {
          :ethernet => {
            :ifconfig => {
              :exec  => '/sbin/ifconfig',
              :regex  => '(\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2})',
              :token  => '(?:ether|HWaddr) ',
            },
          },
        },
        :netmask => {
          :ipv4 => {
            :ifconfig => {
              :exec   => '/sbin/ifconfig',
              :regex  => '(\w+)',
              :token  => 'netmask 0x',
            },
          },
          :ipv6 => {
            :ifconfig => {
              :regex  => '(\w+)',
              :exec   => '/sbin/ifconfig',
              :token  => 'prefixlen ',
            },
          },
        },
      },
    },
    :sunos => {
      :methods => {
        :ipaddress => {
          :ipv4 => {
            :ifconfig => {
              :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :exec  => '/sbin/ifconfig',
              :token => 'inet ',
            },
          },
          :ipv6 => {
            :ifconfig => {
              :regex => '((?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4})',
              :exec  => '/sbin/ifconfig',
              :token => 'inet6 ',
            },
          },
        },
        :macaddress => {
          :ethernet => {
            :ifconfig => {
              :exec  => '/sbin/ifconfig',
              :regex  => '(\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2})',
              :token  => '(?:ether|HWaddr) ',
            },
          },
        },
        :netmask => {
          :ipv4 => {
            :ifconfig => {
              :exec   => '/sbin/ifconfig',
              :regex  => '(\w+)',
              :token  => 'netmask ',
            },
          },
          :ipv6 => {
            :ifconfig => {
              :regex => '(?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4}\/(\d+)',
              :exec   => '/sbin/ifconfig',
              :token  => 'inet6 ',
            },
          },
        },
      },
    },
    :"hp-ux" => {
      :methods => {
        :ipaddress => {
          :ipv4 => {
            :ifconfig => {
              :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :exec  => '/sbin/ifconfig',
              :token => 'inet ',
            },
          },
          :ipv6 => {
            :ifconfig => {
              :regex => '((?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4})',
              :exec  => '/sbin/ifconfig',
              :token => 'inet6 addr: ',
            },
          },
        },
        :macaddress => {
          :ethernet => {
            :lanscan => {
              :exec  => '/sbin/lanscan -a',
              :regex  => '(\w+)',
              :token  => '0x',
            },
          },
        },
        :netmask => {
          :ipv4 => {
            :ifconfig => {
              :exec   => '/sbin/ifconfig',
              :regex  => '(\w+)',
              :token  => 'netmask ',
            },
          },
          :ipv6 => {
            :ifconfig => {
              :regex => '(?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4}\/(\d+)',
              :exec   => '/sbin/ifconfig',
              :token  => 'inet6 ',
            },
          },
        },
      },
    },
    :aix => {
      :methods => {
        :ipaddress => {
          :ipv4 => {
            :ifconfig => {
              :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :exec  => '/sbin/ifconfig -a',
              :token => 'inet ',
            },
          },
          :ipv6 => {
            :ifconfig => {
              :regex => '((?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4})',
              :exec  => '/sbin/ifconfig -a',
              :token => 'inet6 ',
            },
          },
        },
        :macaddress => {
          :ethernet => {
            :ifconfig => {
              :exec  => '/sbin/ifconfig',
              :regex  => '(\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2}:\w{1,2})',
              :token  => '(?:ether|HWaddr) ',
            },
          },
        },
        :netmask => {
          :ipv4 => {
            :ifconfig => {
              :exec   => '/sbin/ifconfig',
              :regex  => '(\w+)',
              :token  => 'netmask ',
            },
          },
          :ipv6 => {
            :ifconfig => {
              :regex => '(?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4}\/(\d+)',
              :exec   => '/sbin/ifconfig',
              :token  => 'inet6 ',
            },
          },
        },
      },
    },
    :windows => {
      :methods => {
        :ipaddress => {
          :ipv4 => {
            :netsh => {
              :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :exec  => "#{ENV['SYSTEMROOT']}/system32/netsh.exe interface ip show interface",
              :token => 'IP Address:\s+',
            },
          },
          :ipv6 => {
            :netsh => {
              :regex => '((?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4})',
              :exec  => "#{ENV['SYSTEMROOT']}/system32/netsh.exe interface ipv6 show interface",
              :token => 'Address\s+',
            },
          },
        },
        :netmask => {
          :ipv4 => {
            :ifconfig => {
              :exec  => "#{ENV['SYSTEMROOT']}/system32/netsh.exe interface ip show interface",
              :regex  => '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
              :token  => 'mask ',
            },
          },
          :ipv6 => {
            :ifconfig => {
              :regex => '(?![fe80|::1])(?>[0-9,a-f,A-F]*\:{1,2})+[0-9,a-f,A-F]{0,4}%(\d+)',
              :exec  => "#{ENV['SYSTEMROOT']}/system32/netsh.exe interface ipv6 show interface",
              :token  => 'Address\s+',
            },
          },
        },
      },
    },
  }

  # Help find specific values in the INTERFACE_MAP nested hash to reduce boilerplate.
  def self.find_value(type, subtype)
    kernel = Facter.value(:kernel).downcase.to_sym
    unless map = INTERFACE_MAP[kernel] || INTERFACE_MAP.values.find { |tmp| tmp[:aliases] and tmp[:aliases].include?(kernel) }
      return []
    end
    return map[:methods][type.to_sym][subtype.to_sym]
  end

  # Extract the information from the output given a token, regex to parse and a regex of addresses to ignore.
  def self.get_item_after_token(output, token, regex, ignore=/^127\./)
    result = nil
    output.scan(/#{token}#{regex}/).each do |match|
      match = match.first
      unless match =~ ignore
        result = match
      end
    end
    result
  end

  def self.find_exec(type, subtype)
    exec = nil
    methods = self.find_value(type, subtype)
    methods.each do |name, method|
      # Strip back to just the file
      if method[:exec]
        file = method[:exec].split(' ').first
        if FileTest.exists?(file)
          exec = method[:exec]
          break
        end
      end
    end
    return exec
  end

  def self.find_entry(item, type, subtype, exec)
    entry = nil
    return entry unless methods = self.find_value(type, subtype)
    methods.each do |name, method|
      if method[:exec] == exec
        entry = method[item.to_sym]
      end
      break unless entry.nil?
    end
    entry
  end

  def self.ipaddress(interface=nil, subtype='ipv4', ignore=/^127\./)
    ipaddress = nil
    exec = Facter::Util::IP.find_exec('ipaddress', subtype)
    token = Facter::Util::IP.find_entry('token', 'ipaddress', subtype, exec)
    regex = Facter::Util::IP.find_entry('regex', 'ipaddress', subtype, exec)

    command = "#{exec}"
    command << " #{interface}" unless interface.nil?

    output = Facter::Util::Resolution.exec(command)
    return [] if output.nil?
    ipaddress = Facter::Util::IP.get_item_after_token(output, token, regex, ignore)

    ipaddress
  end

  # Return an appropriate netmask for an interface.  If the interface displays
  # the netmask in a CIDR format we will automatically convert this to classic
  # style netmasks.
  def self.netmask(interface, subtype='ipv4', ignore=/^127\./)
    netmask = nil
    exec = Facter::Util::IP.find_exec('netmask', subtype)
    token = Facter::Util::IP.find_entry('token', 'netmask', subtype, exec)
    regex = Facter::Util::IP.find_entry('regex', 'netmask', subtype, exec)
    command = "#{exec} #{interface}"

    output = Facter::Util::Resolution.exec(command)
    return [] if output.nil?
    convert = Facter::Util::IP.get_item_after_token(output, token, regex, ignore)
    # Check for a CIDR style match.
    if convert.match(/^\d{1,2}$/)
      netmask = Facter::Util::IP.cidr_to_netmask(convert)
    # FreeBSD returns 0xff00ff00 and HP-UX returns just ff00ff00
    elsif convert.match(/\w{8}/)
      netmask = Facter::Util::IP::hex_to_netmask(convert)
    else
      netmask = convert
    end
    netmask
  end

  def self.macaddress(interface)
    macaddress = nil
    case Facter.value(:kernel).downcase.to_sym
    when :linux
      return nil unless output = File.read("/sys/class/net/#{interface}/address")
      macaddress = output
    else
      exec = Facter::Util::IP.find_exec('macaddress', 'ethernet')
      token = Facter::Util::IP.find_entry('token', 'macaddress', 'ethernet', exec)
      regex = Facter::Util::IP.find_entry('regex', 'macaddress', 'ethernet', exec)

      case Facter.value(:kernel).downcase.to_sym
      when :"hp-ux"
        ppa = interface.slice(-1)
        command = "#{exec} #{ppa}"
      else
        command = "#{exec} #{interface}"
      end

      output = Facter::Util::Resolution.exec(command)
      unless output =~ /interface #{interface} does not exist/
        macaddress = Facter::Util::IP.get_item_after_token(output, token, regex)
      end
    end
    macaddress
  end

  # Convert an interface name into purely alphanumeric characters.
  def self.alphafy(interface)
    interface.gsub(/[^a-z0-9_]/i, '_')
  end

  def self.convert_from_hex?(kernel)
    kernels_to_convert = [:sunos, :openbsd, :netbsd, :freebsd, :darwin, :"hp-ux", :"gnu/kfreebsd", :dragonfly]
    kernels_to_convert.include?(kernel)
  end

  def self.supported_platforms
    REGEX_MAP.inject([]) do |result, tmp|
      key, map = tmp
      if map[:aliases]
        result += map[:aliases]
      else
        result << key
      end
      result
    end
  end

  def self.get_interfaces
    return [] unless output = Facter::Util::IP.get_all_interface_output()

    # windows interface names contain spaces and are quoted and can appear multiple
    # times as ipv4 and ipv6
    return output.scan(/\s* connected\s*(\S.*)/).flatten.uniq if Facter.value(:kernel) == 'windows'

    # Our regex appears to be stupid, in that it leaves colons sitting
    # at the end of interfaces.  So, we have to trim those trailing
    # characters.  I tried making the regex better but supporting all
    # platforms with a single regex is probably a bit too much.
    output.scan(/^\S+/).collect { |i| i.sub(/:$/, '') }.uniq
  end

  def self.get_all_interface_output
    case Facter.value(:kernel)
    when 'Linux', 'OpenBSD', 'NetBSD', 'FreeBSD', 'Darwin', 'GNU/kFreeBSD', 'DragonFly'
      output = %x{/sbin/ifconfig -a 2>/dev/null}
    when 'SunOS'
      output = %x{/usr/sbin/ifconfig -a}
    when 'HP-UX'
      # (#17487)[https://projects.puppetlabs.com/issues/17487]
      # Handle NIC bonding where asterisks and virtual NICs are printed.
      if output = hpux_netstat_in
        output.gsub!(/\*/, "")                  # delete asterisks.
        output.gsub!(/^[^\n]*none[^\n]*\n/, "") # delete lines with 'none' instead of IPs.
        output.sub!(/^[^\n]*\n/, "")            # delete the header line.
        output
      end
    when 'windows'
      output = %x|#{ENV['SYSTEMROOT']}/system32/netsh.exe interface ip show interface|
      output += %x|#{ENV['SYSTEMROOT']}/system32/netsh.exe interface ipv6 show interface|
    end
    output
  end

  ##
  # get_ifconfig simply delegates to the ifconfig command.
  #
  # @return [String] the output of `/sbin/ifconfig 2>/dev/null` or nil
  def self.get_ifconfig
    Facter::Util::Resolution.exec("/sbin/ifconfig 2>/dev/null")
  end

  ##
  # hpux_netstat_in is a delegate method that allows us to stub netstat -in
  # without stubbing exec.
  def self.hpux_netstat_in
    Facter::Util::Resolution.exec("/bin/netstat -in")
  end

  def self.get_infiniband_macaddress(interface)
    if File.exists?("/sys/class/net/#{interface}/address") then
      ib_mac_address = `cat /sys/class/net/#{interface}/address`.chomp
    elsif File.exists?("/sbin/ip") then
      ip_output = %x{/sbin/ip link show #{interface}}
      ib_mac_address = ip_output.scan(%r{infiniband\s+((\w{1,2}:){5,}\w{1,2})})
    else
      ib_mac_address = "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF"
      Facter.debug("ip.rb: nothing under /sys/class/net/#{interface}/address and /sbin/ip not available")
    end
    ib_mac_address
  end

  def self.ifconfig_interface(interface)
    %x{/sbin/ifconfig #{interface} 2>/dev/null}
  end

  def self.get_single_interface_output(interface)
    output = ""
    case Facter.value(:kernel)
    when 'OpenBSD', 'NetBSD', 'FreeBSD', 'Darwin', 'GNU/kFreeBSD', 'DragonFly'
      output = Facter::Util::IP.ifconfig_interface(interface)
    when 'Linux'
      ifconfig_output = Facter::Util::IP.ifconfig_interface(interface)
      if interface =~ /^ib/ then
        real_mac_address = get_infiniband_macaddress(interface)
        output = ifconfig_output.sub(%r{(?:ether|HWaddr)\s+((\w{1,2}:){5,}\w{1,2})}, "HWaddr #{real_mac_address}")
      else
        output = ifconfig_output
      end
    when 'SunOS'
      output = %x{/usr/sbin/ifconfig #{interface}}
    when 'HP-UX'
       mac = ""
       ifc = hpux_ifconfig_interface(interface)
       hpux_lanscan.scan(/(\dx\S+).*UP\s+(\w+\d+)/).each {|i| mac = i[0] if i.include?(interface) }
       mac = mac.sub(/0x(\S+)/,'\1').scan(/../).join(":")
       output = ifc + "\n" + mac
    end
    interfaces
  end

  def self.get_all_interface_output()
    exec4 = Facter::Util::IP.find_exec('ipaddress', 'ipv4')
    exec6 = Facter::Util::IP.find_exec('ipaddress', 'ipv6')

  def self.hpux_ifconfig_interface(interface)
    Facter::Util::Resolution.exec("/usr/sbin/ifconfig #{interface}")
  end

  def self.hpux_lanscan
    Facter::Util::Resolution.exec("/usr/sbin/lanscan")
  end

  def self.get_output_for_interface_and_label(interface, label)
    return get_single_interface_output(interface) unless Facter.value(:kernel) == 'windows'

    case Facter.value(:kernel).downcase.to_sym
    when :solaris
      output = Facter::Util::Resolution.exec(exec4)
    when :"hp-ux"
      output = %x{/bin/netstat -in | sed -e 1d}
    when :windows
      output = %x|#{exec4}|
      output += %x|#{exec6}|
    end
    output
  end


  def self.get_bonding_master(interface)
    if Facter.value(:kernel) != 'Linux'
      return nil
    end
    # We need ip instead of ifconfig because it will show us
    # the bonding master device.
    if not FileTest.executable?("/sbin/ip")
      return nil
    end
    # A bonding interface can never be an alias interface. Alias
    # interfaces do have a colon in their name and the ip link show
    # command throws an error message when we pass it an alias
    # interface.
    if interface =~ /:/
      return nil
    end
    regex = /SLAVE[,>].* (bond[0-9]+)/
      ethbond = regex.match(%x{/sbin/ip link show #{interface}})
    if ethbond
      device = ethbond[1]
    else
      device = nil
    end
    device
  end

  ##
  # get_interface_value obtains the value of a specific attribute of a specific
  # interface.
  #
  # @param interface [String] the interface identifier, e.g. "eth0" or "bond0"
  #
  # @param label [String] the attribute of the interface to obtain a value for,
  # e.g. "netmask" or "ipaddress"
  #
  # @api private
  #
  # @return [String] representing the requested value.  An empty array is
  # returned if the kernel is not supported by the REGEX_MAP constant.
  def self.get_interface_value(interface, label)
    tmp1 = []

    kernel = Facter.value(:kernel).downcase.to_sym

    # If it's not directly in the map or aliased in the map, then we don't know how to deal with it.
    unless map = REGEX_MAP[kernel] || REGEX_MAP.values.find { |tmp| tmp[:aliases] and tmp[:aliases].include?(kernel) }
      return []
    end

    # Pull the correct regex out of the map.
    regex = map[label.to_sym]

    # Linux changes the MAC address reported via ifconfig when an ethernet interface
    # becomes a slave of a bonding device to the master MAC address.
    # We have to dig a bit to get the original/real MAC address of the interface.
    bonddev = get_bonding_master(interface)
    if label == 'macaddress' and bonddev
      bondinfo = read_proc_net_bonding("/proc/net/bonding/#{bonddev}")
      re = /^Slave Interface: #{interface}\b.*?\bPermanent HW addr: (([0-9A-F]{2}:?)*)$/im
      if match = re.match(bondinfo)
        value = match[1].upcase
      end
    else
      output_int = get_output_for_interface_and_label(interface, label)
      output_int.each_line do |s|
        if s =~ regex
          value = $1
            if label == 'netmask' && convert_from_hex?(kernel)
              value = value.scan(/../).collect do |byte| byte.to_i(16) end.join('.')
            end
          tmp1.push(value)
        end
      end

      if tmp1
        value = tmp1.shift
      end
    end
  end

  ##
  # read_proc_net_bonding is a seam method for mocking purposes.
  #
  # @param path [String] representing the path to read, e.g. "/proc/net/bonding/bond0"
  #
  # @api private
  #
  # @return [String] modeling the raw file read
  def self.read_proc_net_bonding(path)
    File.read(path) if File.exists?(path)
  end
  private_class_method :read_proc_net_bonding

  def self.get_network_value(interface)
    require 'ipaddr'

    ipaddress = self.ipaddress(interface)
    netmask = self.netmask(interface)

    if ipaddress && netmask
      ip = IPAddr.new(ipaddress, Socket::AF_INET)
      subnet = IPAddr.new(netmask, Socket::AF_INET)
      network = ip.mask(subnet.to_s).to_s
    end
    network
  end

  def self.get_arp_value(interface)
    arp = Facter::Util::Resolution.exec("arp -en -i #{interface} | sed -e 1d")
    if arp =~ /^\S+\s+\w+\s+(\S+)\s+\w\s+\S+$/
     return $1
    end
  end

  def self.cidr_to_netmask(cidr)
    require 'ipaddr'
    IPAddr.new('255.255.255.255').mask(cidr).to_s
  end

  def self.hex_to_netmask(hex)
    require 'scanf'
    # Yank out the 0x
    stripped = hex.gsub(/^0x/, '')
    stripped.scanf('%2x'*4)*"."
  end


end
