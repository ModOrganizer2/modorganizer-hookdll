#ifndef OBSE_H
#define OBSE_H

struct CommandInfo;
struct ParamInfo;
struct TESObjectREFR;
class Script;
struct ScriptEventList;
typedef UINT32 PluginHandle;

struct OBSEInterface
{
        UINT32  obseVersion;
        UINT32  oblivionVersion;
        UINT32  editorVersion;
        UINT32  isEditor;
        bool    (* RegisterCommand)(CommandInfo * info);        // returns true for success, false for failure
        void    (* SetOpcodeBase)(UINT32 opcode);
        void *  (* QueryInterface)(UINT32 id);

        // added in v0015, only call if obseVersion >= 15
        // call during your Query or Load functions to get a PluginHandle uniquely identifying your plugin
        // invalid if called at any other time, so call it once and save the result
        PluginHandle    (* GetPluginHandle)(void);
};


struct PluginInfo
{
        enum
        {
                kInfoVersion = 1
        };

        UINT32                  infoVersion;
        const char *    name;
        UINT32                  version;
};

#endif // OBSE_H
