fn main() {
    panic!("Execute \"cargo test\" to test the contract, not \"cargo run\".");
}

#[cfg(test)]
mod tests {
    use casper_execution_engine::{
        core::engine_state::Error as EngineStateError,
        storage::global_state::in_memory::InMemoryGlobalState,
    };
    use std::path::PathBuf;

    use casper_engine_test_support::{
        DeployItemBuilder, ExecuteRequestBuilder, InMemoryWasmTestBuilder, WasmTestBuilder,
        ARG_AMOUNT, DEFAULT_ACCOUNT_ADDR, DEFAULT_PAYMENT, PRODUCTION_RUN_GENESIS_REQUEST,
    };
    use casper_execution_engine::core::execution;
    use casper_types::{runtime_args, ApiError, ContractHash, RuntimeArgs};

    const VALUE: u32 = 1;
    const RUNTIME_ARG_NAME: &str = "number";
    const ENTRY_POINT_INIT: &str = "init";
    const ENTRY_POINT_VALIDATE_PAUSE: &str = "validate_pause";
    const CONTRACT_WASM: &str = "contract.wasm";
    pub const CONTRACT_NAME: &str = "this_contract1";

    #[test]
    fn should_call_init_and_validate_pause_and_error() {
        let mut builder = InMemoryWasmTestBuilder::default();
        builder
            .run_genesis(&PRODUCTION_RUN_GENESIS_REQUEST)
            .commit();

        // The test framework checks for compiled Wasm files in '<current working dir>/wasm'.  Paths
        // relative to the current working dir (e.g. 'wasm/contract.wasm') can also be used, as can
        // absolute paths.
        let session_code = PathBuf::from(CONTRACT_WASM);
        let session_args = runtime_args! {
            RUNTIME_ARG_NAME => casper_types::U512::from(VALUE),
        };

        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {
                ARG_AMOUNT => *DEFAULT_PAYMENT
            })
            .with_session_code(session_code, session_args)
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .build();

        let execute_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();

        // deploy the contract.
        builder.exec(execute_request).commit().expect_success();

        let contract_hash = get_contract_hash(&builder);

        let group_key: [u8; 32] = [7u8; 32];
        let fee_public_key: [u8; 32] = [8u8; 32];
        let whitelist = vec![ContractHash::from([9u8; 32])];

        let init_request = ExecuteRequestBuilder::contract_call_by_hash(
            *DEFAULT_ACCOUNT_ADDR,
            contract_hash,
            ENTRY_POINT_INIT,
            runtime_args! {
                "group_key" => group_key,
                "fee_public_key" => fee_public_key,
                "whitelist" => whitelist,
            },
        )
        .build();

        builder.exec(init_request).expect_success().commit();

        let action_id = 123_u32;
        let sig_data: [u8; 64] = [10u8; 64];

        let validate_pause_request = ExecuteRequestBuilder::contract_call_by_hash(
            *DEFAULT_ACCOUNT_ADDR,
            contract_hash,
            ENTRY_POINT_VALIDATE_PAUSE,
            runtime_args! {
                "action_id" => casper_types::U256::from(action_id),
                "sig_data" => sig_data,
            },
        )
        .build();

        builder
            .exec(validate_pause_request)
            .commit()
            .expect_failure();

        let error_code: u16 = 30;

        let actual_error = builder.get_error().expect("must have error");
        let reason = "should revert on verify";
        let actual = format!("{actual_error:?}");
        let expected = format!(
            "{:?}",
            EngineStateError::Exec(execution::Error::Revert(ApiError::User(error_code)))
        );

        assert_eq!(
            actual, expected,
            "Error should match {error_code} with reason: {reason}"
        )
    }

    #[test]
    fn should_error_on_missing_runtime_arg() {
        let session_code = PathBuf::from(CONTRACT_WASM);
        let session_args = RuntimeArgs::new();

        let deploy_item = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
            .with_address(*DEFAULT_ACCOUNT_ADDR)
            .with_session_code(session_code, session_args)
            .build();

        let execute_request = ExecuteRequestBuilder::from_deploy_item(deploy_item).build();

        let mut builder = InMemoryWasmTestBuilder::default();
        builder
            .run_genesis(&PRODUCTION_RUN_GENESIS_REQUEST)
            .commit();
        builder.exec(execute_request).commit().expect_failure();

        let error = ApiError::MissingArgument;
        let error_code: u32 = error.into();
        let actual_error = builder.get_error().expect("must have error");
        let reason = "should error on missing runtime_arg";
        let actual = format!("{actual_error:?}");
        let expected = format!(
            "{:?}",
            EngineStateError::Exec(execution::Error::Revert(error))
        );

        assert_eq!(
            actual, expected,
            "Error should match {error_code} with reason: {reason}"
        )
    }

    fn get_contract_hash(builder: &WasmTestBuilder<InMemoryGlobalState>) -> ContractHash {
        let hash_addr = builder
            .get_expected_account(*DEFAULT_ACCOUNT_ADDR)
            .named_keys()
            .get(CONTRACT_NAME)
            .expect("must have this entry in named keys")
            .into_hash()
            .expect("must get hash_addr");

        ContractHash::new(hash_addr)
    }
}
