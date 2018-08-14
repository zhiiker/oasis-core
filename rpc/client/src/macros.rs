// This is re-exported here only so it can be used in macros under a common name.
pub use ekiden_common::futures::prelude::*;
pub use ekiden_enclave_common::quote;

/// Create an RPC client for a given API.
///
/// # Examples
///
/// This macro should be invoked using a concrete API generated by `rpc_api` as
/// follows:
/// ```rust,ignore
/// with_api! {
///     create_client_rpc!(foo, foo_api, api);
/// }
/// ```
///
/// In this example, the generated client will be put into a module called `foo`
/// which will use API structures from module `foo_api`. The API definitions will
/// passed as the last argument as defined by the `api` token.
#[macro_export]
macro_rules! create_client_rpc {
    (
        $output_module: ident,
        $api_module: path,

        metadata {
            name = $metadata_name: ident ;
            version = $metadata_version: expr ;
            client_attestation_required = $client_attestation_required: expr ;
        }

        $(
            $(#[$($attribute:tt)*])*
            rpc $method_name: ident ( $request_type: ty ) -> $response_type: ty ;
        )*
    ) => {
        mod $output_module {
            use std::sync::Arc;

            use $crate::*;
            use $crate::backend::RpcClientBackend;
            use $crate::macros::*;

            pub use $api_module::*;

            pub struct Client<Backend: RpcClientBackend + 'static> {
                client: RpcClient<Backend>,
            }

            #[allow(dead_code)]
            impl<Backend: RpcClientBackend + 'static> Client<Backend> {
                /// Create new client instance.
                ///
                /// If you set `client_authentication` to `None` the default value from the API
                /// definition will be used. Otherwise this option can be used to override whether
                /// client authentication is enabled.
                pub fn new(
                    backend: Arc<Backend>,
                    mr_enclave: $crate::macros::quote::MrEnclave,
                    client_authentication: Option<bool>
                ) -> Self {
                    Self {
                        client: RpcClient::new(
                            backend,
                            mr_enclave,
                            if let Some(client_authentication) = client_authentication {
                                client_authentication
                            } else {
                                $client_attestation_required
                            },
                        ),
                    }
                }

                /// Initialize a secure channel with the contract.
                ///
                /// If this method is not called, secure channel is automatically initialized
                /// when making the first request.
                pub fn init_secure_channel(&self) -> BoxFuture<()> {
                    self.client.init_secure_channel()
                }

                /// Close secure channel.
                ///
                /// If this method is not called, secure channel is automatically closed in
                /// a blocking fashion when the client is dropped.
                pub fn close_secure_channel(&self) -> BoxFuture<()> {
                    self.client.close_secure_channel()
                }

                // Generate methods.
                $(
                    pub fn $method_name(
                        &self,
                        request: $request_type
                    ) -> BoxFuture<$response_type> {
                        self.client.call(stringify!($method_name), request)
                    }
                )*
            }
        }
    };
}
