module "yeti" {
    management {
        #each node sections describes management node, specify multiple nodes for failover
        #node {
        #    address = localhost
        #    port = 4444
        #}

        # maximum time for waiting remote config (ms)
        #timeout = 5000
    }

    # process OPTIONS requests
    #core_options_handling = yes
}
