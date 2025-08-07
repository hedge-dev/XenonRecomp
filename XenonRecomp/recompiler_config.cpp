#include "recompiler_config.h"

void RecompilerConfig::Load(const std::string_view& configFilePath)
{
    directoryPath = configFilePath.substr(0, configFilePath.find_last_of("\\/") + 1);
    toml::table toml = toml::parse_file(configFilePath)
#if !TOML_EXCEPTIONS
        .table()
#endif
        ;

    if (auto mainPtr = toml["main"].as_table())
    {
        const auto& main = *mainPtr;
        filePath = main["file_path"].value_or<std::string>("");
        patchFilePath = main["patch_file_path"].value_or<std::string>("");
        patchedFilePath = main["patched_file_path"].value_or<std::string>("");
        outDirectoryPath = main["out_directory_path"].value_or<std::string>("");
        switchTableFilePath = main["switch_table_file_path"].value_or<std::string>("");

        skipLr = main["skip_lr"].value_or(false);
        skipMsr = main["skip_msr"].value_or(false);
        ctrAsLocalVariable = main["ctr_as_local"].value_or(false);
        xerAsLocalVariable = main["xer_as_local"].value_or(false);
        reservedRegisterAsLocalVariable = main["reserved_as_local"].value_or(false);
        crRegistersAsLocalVariables = main["cr_as_local"].value_or(false);
        nonArgumentRegistersAsLocalVariables = main["non_argument_as_local"].value_or(false);
        nonVolatileRegistersAsLocalVariables = main["non_volatile_as_local"].value_or(false);

        restGpr14Address = main["restgprlr_14_address"].value_or(0u);
        saveGpr14Address = main["savegprlr_14_address"].value_or(0u);
        restFpr14Address = main["restfpr_14_address"].value_or(0u);
        saveFpr14Address = main["savefpr_14_address"].value_or(0u);
        restVmx14Address = main["restvmx_14_address"].value_or(0u);
        saveVmx14Address = main["savevmx_14_address"].value_or(0u);
        restVmx64Address = main["restvmx_64_address"].value_or(0u);
        saveVmx64Address = main["savevmx_64_address"].value_or(0u);
        longJmpAddress = main["longjmp_address"].value_or(0u);
        setJmpAddress = main["setjmp_address"].value_or(0u);

        if (restGpr14Address == 0) fmt::println("ERROR: __restgprlr_14 address is unspecified");
        if (saveGpr14Address == 0) fmt::println("ERROR: __savegprlr_14 address is unspecified");
        if (restFpr14Address == 0) fmt::println("ERROR: __restfpr_14 address is unspecified");
        if (saveFpr14Address == 0) fmt::println("ERROR: __savefpr_14 address is unspecified");
        if (restVmx14Address == 0) fmt::println("ERROR: __restvmx_14 address is unspecified");
        if (saveVmx14Address == 0) fmt::println("ERROR: __savevmx_14 address is unspecified");
        if (restVmx64Address == 0) fmt::println("ERROR: __restvmx_64 address is unspecified");
        if (saveVmx64Address == 0) fmt::println("ERROR: __savevmx_64 address is unspecified");

        if (auto functionsArray = main["functions"].as_array())
        {
            for (auto& func : *functionsArray)
            {
                auto& funcTable = *func.as_table();
                uint32_t address = *funcTable["address"].value<uint32_t>();
                uint32_t size = *funcTable["size"].value<uint32_t>();
                functions.emplace(address, size);
            }
        }

        if (auto invalidArray = main["invalid_instructions"].as_array())
        {
            for (auto& instr : *invalidArray)
            {
                auto& instrTable = *instr.as_table();
                uint32_t data = *instrTable["data"].value<uint32_t>();
                uint32_t size = *instrTable["size"].value<uint32_t>();
                invalidInstructions.emplace(data, size);
            }
        }

        if (!switchTableFilePath.empty())
        {
            toml::table switchToml = toml::parse_file(directoryPath + switchTableFilePath)
#if !TOML_EXCEPTIONS
                .table()
#endif
                ;
            if (auto switchArray = switchToml["switch"].as_array())
            {
                for (auto& entry : *switchArray)
                {
                    auto& table = *entry.as_table();
                    RecompilerSwitchTable switchTable;
                    switchTable.r = *table["r"].value<uint32_t>();
                    for (auto& label : *table["labels"].as_array())
                    {
                        switchTable.labels.push_back(*label.value<uint32_t>());
                    }
                    switchTables.emplace(*table["base"].value<uint32_t>(), std::move(switchTable));
                }
            }
        }
    }

    if (auto midAsmHookArray = toml["midasm_hook"].as_array())
    {
        for (auto& entry : *midAsmHookArray)
        {
            auto& table = *entry.as_table();

            RecompilerMidAsmHook midAsmHook;
            midAsmHook.name = *table["name"].value<std::string>();
            if (auto registerArray = table["registers"].as_array())
            {
                for (auto& reg : *registerArray)
                    midAsmHook.registers.push_back(*reg.value<std::string>());
            }

            midAsmHook.ret = table["return"].value_or(false);
            midAsmHook.returnOnTrue = table["return_on_true"].value_or(false);
            midAsmHook.returnOnFalse = table["return_on_false"].value_or(false);

            midAsmHook.jumpAddress = table["jump_address"].value_or(0u);
            midAsmHook.jumpAddressOnTrue = table["jump_address_on_true"].value_or(0u);
            midAsmHook.jumpAddressOnFalse = table["jump_address_on_false"].value_or(0u);

            if ((midAsmHook.ret && midAsmHook.jumpAddress != 0) ||
                (midAsmHook.returnOnTrue && midAsmHook.jumpAddressOnTrue != 0) ||
                (midAsmHook.returnOnFalse && midAsmHook.jumpAddressOnFalse != 0))
            {
                fmt::println("{}: can't return and jump at the same time", midAsmHook.name);
            }

            if ((midAsmHook.ret || midAsmHook.jumpAddress != 0) &&
                (midAsmHook.returnOnFalse != 0 || midAsmHook.returnOnTrue != 0 ||
                    midAsmHook.jumpAddressOnFalse != 0 || midAsmHook.jumpAddressOnTrue != 0))
            {
                fmt::println("{}: can't mix direct and conditional return/jump", midAsmHook.name);
            }

            midAsmHook.afterInstruction = table["after_instruction"].value_or(false);

            midAsmHooks.emplace(*table["address"].value<uint32_t>(), std::move(midAsmHook));
        }
    }
}
