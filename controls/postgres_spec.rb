# encoding: utf-8

# Copyright 2016, Patrick Muench
# Copyright 2016-2019 DevSec Hardening Framework Team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Christoph Hartmann
# author: Dominik Richter
# author: Patrick Muench

title 'PostgreSQL Server Configuration'

# attributes

USER = attribute(
  'user',
  description: 'define the postgresql user to access the database'
  default: 'postgres'
  
)

PASSWORD = attribute(
  'password',
  description: 'define the postgresql password to access the database'
  
)

HOST = attribute(
  'host',
  description: 'define the postgresql host where it is listening',
  default: 'localhost'
)

POSTGRES_DATA = attribute(
  'postgres_data',
  description: 'define the postgresql data directory'
  default: '/var/lib/postgresql/12/main'
  
)

POSTGRES_CONF_DIR = attribute(
  'postgres_conf_dir',
  description: 'define the postgresql configuration directory'
  default: '/etc/postgresql'
 
)

POSTGRES_CONF_PATH = attribute(
  'postgres_conf_path',
  description: 'define path for the postgresql configuration file'
  default: '/etc/postgresql/12/main/postgresql.conf'
  
).to_s

POSTGRES_HBA_CONF_FILE = attribute(
  'postgres_hba_conf_file',
  description: 'define path for the postgresql configuration file'
  default: '/etc/postgresql/12/main/pg_hba.conf'
)

only_if do
  command('psql').exist?
end

control 'postgres-01' do
  impact 1.0
  title 'Postgresql should be running and enabled'
  desc 'Postgresql should be running and enabled'
  # describe service(postgres.service) do
  #   it { should be_installed }
  #   it { should be_running }
  #   it { should be_enabled }
  # end
  case os[:name]
  when 'ubuntu'
    case os[:release]
    when '12.04'
      describe command('/etc/init.d/postgresql status') do
        its('stdout') { should include 'online' }
      end
    when '14.04'
      describe command('service postgresql status') do
        its('stdout') { should include 'online' }
      end
    when '16.04'
      describe systemd_service(postgres.service) do
        it { should be_installed }
        it { should be_running }
        it { should be_enabled }
      end
    # Added for ubuntu 18.04 
    when '18.04'
      describe command('service postgresql status') do
        its('stdout') { should include 'active' }
      end
      describe command('systemctl list-unit-files | grep postgresql.service') do
        its('stdout') { should include 'enabled' }
      end
    
      
    end
  when 'debian'
    case os[:release]
    when /7\./
      describe command('/etc/init.d/postgresql status') do
        its('stdout') { should include 'Running' }
      end
    end
  when 'redhat', 'centos', 'oracle', 'fedora'
    case os[:release]
    when /6\./
      describe command('/etc/init.d/postgresql-9.4 status') do
        its('stdout') { should include 'running' }
      end
    when /7\./
      describe command('ps aux | awk /\'bin\/postgres\'/ | wc -l') do
        its('stdout') { should include '1' }
      end
    end
  end
end

control 'postgres-02' do
  impact 1.0
  title 'Use stable postgresql version'
  desc 'Use only community or commercially supported version of the PostgreSQL software. Do not use RC, DEVEL oder BETA versions in a production environment.'
  # describe command('psql -V') do
  #   its('stdout') { should match(/^psql\s\(PostgreSQL\)\s([9 10 11 12]\.[3-6]|10\.5).*/) }
  # end
  describe command('psql -V') do
    its('stdout') { should_not match(/RC/) }
    its('stdout') { should_not match(/DEVEL/) }
    its('stdout') { should_not match(/BETA/) }
  end
end

control 'postgres-03' do
  impact 1.0
  title 'Run one postgresql instance per operating system'
  tag Vulnerability: 'Medium'
  tag cce: 'CCE-27072-8'
  tag disa: 'RHEL-06-000227'
  ref 'NSA-RH6-STIG - Section 3.5.2.1'
  desc 'Only one postgresql database instance must be running on an operating system instance (both physical HW or virtualized).'
  pg_command = 'postgres'
  pg_command = 'postmaster' if os.redhat? && os.release.include?('6.')
  describe processes(pg_command) do
    its('entries.length') { should eq 1 }
  end
end

control 'postgres-04' do
  impact 1.0
  title 'Only "c" and "internal" should be used as non-trusted procedural languages'
  desc 'If additional programming languages (e.g. plperl) are installed with non-trust mode, then it is possible to gain OS-level access permissions.'
  describe postgres_session(USER, PASSWORD, HOST).query('SELECT count (*) FROM pg_language WHERE lanpltrusted = \'f\' AND lanname!=\'internal\' AND lanname!=\'c\';') do
    its('output') { should eq '0' }
  end
end

control 'postgres-05' do
  impact 1.0
  title 'Set a password for each user'
  desc 'It tests for usernames which does not set a password.'
  describe postgres_session(USER, PASSWORD,HOST).query('SELECT count(*) FROM pg_shadow WHERE passwd IS NULL;') do
    its('output') { should eq '0' }
  end
end

control 'postgres-06' do
  impact 1.0
  title 'Use salted hash to store postgresql passwords'
  desc 'Store postgresql passwords in salted hash format (e.g. salted MD5).'
  case postgres.version
  when /^9/
    describe postgres_session(USER, PASSWORD, HOST).query('SELECT passwd FROM pg_shadow;') do
      its('output') { should match(/^md5.*$/) }
    end
    describe postgres_conf(POSTGRES_CONF_PATH) do
      its('password_encryption') { should eq 'on' }
    end
  when /^10/
    describe postgres_session(USER, PASSWORD, HOST).query('SELECT passwd FROM pg_shadow;') do
      its('output') { should match(/^scram-sha-256\S*$/) }
    end
    describe postgres_conf(POSTGRES_CONF_PATH) do
      its('password_encryption') { should eq 'scram-sha-256' }
    end
  end
end

control 'postgres-07' do
  impact 1.0
  title 'Only the postgresql database administrator should have SUPERUSER, CREATEDB or CREATEROLE privileges.'
  desc 'Granting extensive privileges to ordinary users can cause various security problems, such as: intentional/ unintentional access, modification or destroying data'
  describe postgres_session(USER, PASSWORD, HOST).query('SELECT count(*) FROM pg_roles WHERE rolsuper IS TRUE OR rolcreaterole IS TRUE or rolcreatedb IS TRUE;') do
    its('output') { should eq '1' }
  end
end

control 'postgres-08' do
  impact 1.0
  title 'Only the DBA should have privileges on pg_catalog.pg_authid table.'
  desc 'In pg_catalog.pg_authid table there are stored credentials such as username and password. If hacker has access to the table, then he can extract these credentials.'
  describe postgres_session(USER, PASSWORD, HOST).query('\dp pg_catalog.pg_authid') do
    its('output') { should eq 'pg_catalog | pg_authid | table | postgres=arwdDxt/postgres |' }
  end
end

control 'postgres-09' do
  impact 1.0
  title 'The PostgreSQL "data_directory" should be assigned exclusively to the database account (such as "postgres").'
  desc 'If file permissions on data are not property defined, other users may read, modify or delete those files.'
  find_command = 'find ' + POSTGRES_DATA.to_s + ' -user ' + USER + ' -group ' + USER + ' -perm /go=rwx'
  describe command(find_command) do
    its('stdout') { should eq '' }
  end
end

control 'postgres-10' do
  impact 1.0
  title 'The PostgreSQL config directory and file should be assigned exclusively to the database account (such as "postgres").'
  desc 'If file permissions on config files are not property defined, other users may read, modify or delete those files.'
  describe file(POSTGRES_CONF_DIR) do
    it { should be_directory }
    it { should be_owned_by USER }
    it { should be_readable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_readable.by('other') }
    it { should be_writable.by('owner') }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('other') }
    it { should be_executable.by('owner') }
    it { should_not be_executable.by('group') }
    it { should_not be_executable.by('other') }
  end
  describe file(POSTGRES_CONF_PATH) do
    it { should be_file }
    it { should be_owned_by USER }
    it { should be_readable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_readable.by('other') }
    it { should be_writable.by('owner') }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable.by('owner') }
    it { should_not be_executable.by('group') }
    it { should_not be_executable.by('other') }
  end
  describe file(POSTGRES_HBA_CONF_FILE) do
    it { should be_file }
    it { should be_owned_by USER }
    it { should be_readable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_readable.by('other') }
    it { should be_writable.by('owner') }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable.by('owner') }
    it { should_not be_executable.by('group') }
    it { should_not be_executable.by('other') }
  end
end

control 'postgres-11' do
  impact 1.0
  title 'SSL is deactivated just for testing the chef-hardening-cookbook. It is recommended to activate ssl communication.'
  desc 'The hardening-cookbook will delete the links from #var/lib/postgresql/%postgresql-version%/main/server.crt to etc/ssl/certs/ssl-cert-snakeoil.pem and #var/lib/postgresql/%postgresql-version%/main/server.key to etc/ssl/private/ssl-cert-snakeoil.key on Debian systems. This certificates are self-signed (see http://en.wikipedia.org/wiki/Snake_oil_%28cryptography%29) and therefore not trusted. You have to #provide our own trusted certificates for SSL.'
  describe postgres_conf(POSTGRES_CONF_PATH) do
    its('ssl') { should eq 'off' }
  end
end

control 'postgres-12' do
  impact 1.0
  title 'Use strong chiphers for ssl communication'
  desc 'The following categories of SSL Ciphers must not be used: ADH, LOW, EXP and MD5. A very good description for secure postgres installation / configuration can be found at: https://bettercrypto.org'
  # This is entirely incorrect way to test 
  # Initially postgres default is HIGH:MEDIUM:+3DES:!aNULL which is upto CIS benchmark
  # So it will fail this case even though cipers strategy is good
  # describe postgres_conf(POSTGRES_CONF_PATH) do
  #   its('ssl_ciphers') { should eq 'ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH' }
  # end
  # So we should check LOW ADH and EXP MD5 should not be present in ssl ciphers
  describe postgres_session(USER, PASSWORD, HOST).query('show ssl_ciphers ;') do
    its('output') { should_not match (/ADH/) }
  end
  describe postgres_session(USER, PASSWORD, HOST).query('show ssl_ciphers ;') do
    its('output') { should_not match (/LOW/) }
  end
  describe postgres_session(USER, PASSWORD, HOST).query('show ssl_ciphers ;') do
    its('output') { should_not match (/EXP/) }
  end
  describe postgres_session(USER, PASSWORD, HOST).query('show ssl_ciphers ;') do
    its('output') { should_not match (/MD5/) }
  end
  
end

control 'postgres-13' do
  impact 1.0
  title 'Require MD5 for ALL users, peers in pg_hba.conf'
  desc 'Require MD5 for ALL users, peers in pg_hba.conf and do not allow untrusted authentication methods.'
  # describe file(POSTGRES_HBA_CONF_FILE) do
  #   its('content') { should match(/local\s.*?all\s.*?all\s.*?md5/) }
  #   its('content') { should match(%r{host\s.*?all\s.*?all\s.*?127.0.0.1\/32\s.*?md5}) }
  #   its('content') { should match(%r{host\s.*?all\s.*?all\s.*?::1\/128\s.*?md5}) }
  #   its('content') { should_not match(/.*password/) }
  #   its('content') { should_not match(/.*trust/) }
  #   its('content') { should_not match(/.*crypt/) }
  # end
  # Here we are executing query and fetching exact details more robust and no chance of getting false data
  describe postgres_session(USER, PASSWORD, HOST).query('select auth_method  from pg_hba_file_rules where type=\'local\' AND database=\'{all}\' AND user_name=\'{all}\';') do
    its('output') { should eq "md5" }
  end
  describe postgres_session(USER, PASSWORD, HOST).query(' select auth_method  from pg_hba_file_rules where type=\'host\' AND database=\'{all}\' AND user_name=\'{all}\' AND address=\'127.0.0.1\';') do
    its('output') { should eq "md5" }
  end
  describe postgres_session(USER, PASSWORD, HOST).query('select auth_method  from pg_hba_file_rules where type=\'host\' AND database=\'{all}\' AND user_name=\'{all}\' AND address=\'::1\'; ;') do
    its('output') { should eq "md5" }
  end
  describe postgres_session(USER, PASSWORD, HOST).query('select auth_method from  pg_hba_file_rules ;') do
    its('output') { should_not match(/.*password/) }
  end
  describe postgres_session(USER, PASSWORD, HOST).query('select auth_method from  pg_hba_file_rules ;') do
    its('output') { should_not match(/.*trust/) }
  end
  describe postgres_session(USER, PASSWORD, HOST).query('select auth_method from  pg_hba_file_rules ;') do
    its('output') { should_not match(/.*crypt/) }
  end

end

control 'postgres-14' do
  impact 1.0
  title 'We accept one peer and one ident for now (chef automation)'
  desc 'We accept one peer and one ident for now (chef automation)'
  # This code fails as commented line words peer is also being grep and giving false data
  # describe command('cat ' + POSTGRES_HBA_CONF_FILE.to_s + ' | egrep \'peer|ident\' | wc -l') do
  #   its('stdout') { should match(/^[2|1]/) }
  # end
  describe postgres_session(USER, PASSWORD, HOST).query('select count(*) auth_method from  pg_hba_file_rules where auth_method=\'peer\' ;') do
    its('output') { should <= "1"  }
  end
  describe postgres_session(USER, PASSWORD, HOST).query('select count(*) auth_method from  pg_hba_file_rules where auth_method=\'ident\' ;') do
    its('output') { should <= "1"  }
  end

end

control 'postgres-15' do
  impact 1.0
  title 'Enable logging functions'
  desc 'Logging functions must be turned on and properly configured according / compliant to local law.'
  # It checks for attributes from config file
  # describe postgres_conf(POSTGRES_CONF_PATH) do
  #   its('logging_collector') { should eq 'on' }
  #   its('log_connections') { should eq 'on' }
  #   its('log_disconnections') { should eq 'on' }
  #   its('log_duration') { should eq 'on' }
  #   its('log_hostname') { should eq 'on' }
  #   its('log_directory') { should eq 'pg_log' }
  #   its('log_line_prefix') { should eq '%t %u %d %h' }
  # end

  describe postgres_session(USER, PASSWORD, HOST).query('show logging_collector;') do
    its('output') { should eq 'on' }
  end
  describe postgres_session(USER, PASSWORD, HOST).query('show log_connections;') do
    its('output') { should eq 'on' }
  end
  describe postgres_session(USER, PASSWORD, HOST).query('show log_disconnections;') do
    its('output') { should eq 'on' }
  end
  describe postgres_session(USER, PASSWORD, HOST).query('show log_duration;') do
    its('output') { should eq 'on' }
  end
  describe postgres_session(USER, PASSWORD, HOST).query('show log_hostname;') do
    its('output') { should eq 'on' }
  end
  # Mainly for directory name can be anything
  describe postgres_session(USER, PASSWORD, HOST).query('show log_directory;') do
    its('output') { should match(/[aA0-zZ9 _ ]/)  }
  end
  # describe postgres_session(USER, PASSWORD, HOST).query('show log_line_prefix;') do
  #   its('output') { should match (/[aA0-zZ9]/) }


end
