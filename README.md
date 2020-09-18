# DevSec PostgreSQL Baseline

This Compliance Profile ensures, that all hardening projects keep the same quality.

- https://github.com/dev-sec/chef-postgres-hardening
- https://github.com/dev-sec/puppet-postgres-hardening

## Standalone Usage

This Compliance Profile requires [InSpec](https://github.com/chef/inspec) for execution:

```
$ git clone https://github.com/dev-sec/postgres-baseline
$ inspec exec postgres-baseline
```

You can also execute the profile directly from Github:

```
$ inspec exec https://github.com/dev-sec/postgres-baseline
```

## License and Author

- Author:: Patrick Muench <patrick.muench1111@gmail.com >
- Author:: Dominik Richter <dominik.richter@googlemail.com>
- Author:: Christoph Hartmann <chris@lollyrock.com>
- Author:: Edmund Haselwanter <me@ehaselwanter.com>

- Copyright 2014-2019, The DevSec Hardening Framework Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Purpose 
Database are key component and main target of any attacker. Database stored information should be exposed by any means.
The aim of this tool is to check postgresl  being used is configured as per CIS Benchmark Standards.
No means can access your postgresql when we implement it as per CIS Benchmark.

## Attributes

To check your postgresl it requires following attributes.

|**Paramter Name**| **Type** | **Description** | **Default Value** |
|-----------------|----------|-----------------|
| user | *mandatory* | Your database user, this tool execute some query in postgresql for which we will be needing any database user | postgres | 
| password | *mandatory* |  Your database password, this tool execute some query in postgresql for which we will be needing password of given database user |  No   |
| host | *mandatory* | host is ip address or dns name where postgresql is listening | localhost |
| postgres_conf_dir | *mandatory* | Postgresql configuration Directory | /var/lib/postgresql/12/main |
| postgres_conf_path | *mandatory* | In which format you want result Available options are HTML,XML,CSV etc. | /etc/postgresql/12/main |
| postgres_hba_conf_file | *manadatory* | Name of the slack channel in which notification should be sent | /etc/postgresql/12/main  |

## How to pass attributes

Their are two ways to pass attributes

### inspec.yml

In inspec.yml 

```
attributes:
  - name: postgres_data
    value: "/var/lib/postgres/10"
  - name: postgres_conf_dir
    value: "/etc/postgresql"
  - name: postgres_conf_path
    value: "/etc/postgresql/10/main/postgresql.conf"
  - name: postgres_hba_conf_file
    value: "/etc/postgresql/10/main/pg_hba.conf"
  - name: "user"
    value: "postgres"
  - name: password
    value: "root"
  - name: "host"
    value: "127.0.0.1"

```
Replace this attributes with your own

### CLI

Execute inspec in following ways

```
inspec exec postgres-baseline --input user=postgres password=root host=172.1.1.1 

```