hosts:
  - 1513629884013:   # this exact id is what the image entrypoint greps for -
                     # any other name makes it append a duplicate hosts block
      url: "https://wazuh.master"
      port: 55000
      username: wazuh-wui
      password: "REPLACE_WITH_API_PASSWORD"
      run_as: true
