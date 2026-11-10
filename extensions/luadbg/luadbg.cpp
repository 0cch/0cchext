// luadbg.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "lua.hpp"
#include <mutex>

class EXT_CLASS : public ExtExtension
{
public:
	EXT_COMMAND_METHOD(lua);
	EXT_COMMAND_METHOD(luacmd);
	EXT_COMMAND_METHOD(luaload);
	EXT_COMMAND_METHOD(luaunload);
	EXT_COMMAND_METHOD(luado);
	EXT_COMMAND_METHOD(lualist);

	virtual void Uninitialize(void);
};

EXT_DECLARE_GLOBALS();

static int dbgprint(lua_State* L)
{
	int nargs = lua_gettop(L);
	for (int i = 1; i <= nargs; ++i) {
		const char *text = luaL_tolstring(L, i, NULL);
		if (i > 1) {
			g_Ext->Out("\t");
		}
		g_Ext->Out("%s", text != NULL ? text : "(null)");
		lua_pop(L, 1);
	}
	g_Ext->Out("\r\n");

	return 0;
}

static bool CopyLuaString(char *dest, size_t capacity, const char *src)
{
	if (dest == NULL || src == NULL || capacity == 0) {
		return false;
	}
	size_t length = strlen(src);
	if (length >= capacity) {
		return false;
	}
	memcpy(dest, src, length + 1);
	return true;
}
static const struct luaL_Reg printlib[] = {
	{"print", dbgprint},
	{NULL, NULL} /* end of array */
};

void SetDefaultPrint(lua_State* L)
{
	lua_getglobal(L, "_G");
	luaL_setfuncs(L, printlib, 0);
	lua_pop(L, 1);
}


/************************************************************************/
/*                        dbgmodule                                     */
/************************************************************************/


typedef struct _DBG_MODULE {
	ULONG64 ModuleAddr;
	CHAR ModuleName[1024];
} DBG_MODULE;

static int dbgmodule_new(lua_State *L)
{
	const char *module_name = luaL_checkstring(L, 1);
	ULONG index = 0;
	ULONG64 addr = 0;
	if (FAILED(g_Ext->m_Symbols->GetModuleByModuleName(module_name, 0, &index, &addr)) || addr == 0) {
		lua_pushnil(L);
		return 1;
	}

	DBG_MODULE *m = (DBG_MODULE *)lua_newuserdata(L, sizeof(DBG_MODULE));

	luaL_getmetatable(L, "dbgmodule.metatable");
	lua_setmetatable(L, -2);

	m->ModuleAddr = addr;
	if (!CopyLuaString(m->ModuleName, sizeof(m->ModuleName), module_name)) {
		lua_pop(L, 1);
		lua_pushnil(L);
	}

	return 1;
}

static DBG_MODULE *dbgmodule_check(lua_State *L)
{
	void *ud = luaL_checkudata(L, 1, "dbgmodule.metatable");
	luaL_argcheck(L, ud != NULL, 1, "`dbgmodule' expected");
	return (DBG_MODULE *)ud;
}

static int dbgmodule_getname(lua_State *L)
{
	DBG_MODULE *m = dbgmodule_check(L);
	lua_pushstring(L, m->ModuleName);
	return 1;
}

static int dbgmodule_getaddr(lua_State *L)
{
	DBG_MODULE *m = dbgmodule_check(L);
	lua_pushinteger(L, m->ModuleAddr);
	return 1;
}

static const struct luaL_Reg dbgmodule_lib [] = {
	{"new", dbgmodule_new},
	{NULL, NULL}
};

static int dbgmodule___index(lua_State *L)
{
	const char *member_name = luaL_checkstring(L, -1);

	lua_getmetatable(L, -2);
	lua_pushstring(L, member_name);
	lua_rawget(L,-2);
	lua_remove(L,-2);
	if (lua_isfunction(L, -1))
	{
		lua_remove(L, -2);
		return 1;
	}
	DBG_MODULE *m = dbgmodule_check(L);
	const char* key = member_name;

	CStringA sym_name;
	sym_name.Format("%s!%s", m->ModuleName, key);

	ULONG64 off = 0;
	if (FAILED(g_Ext->m_Symbols->GetOffsetByName(sym_name.GetString(), &off))) {
		lua_pushstring(L, "cannot find symbol.");
		return 1;
	}

	lua_pushinteger(L, off);

	return 1;
}

static const struct luaL_Reg dbgmodule_func[] = {
	{ "__index", dbgmodule___index },
	{ "addr", dbgmodule_getaddr },
	{ "name", dbgmodule_getname },
	{ NULL, NULL }
};

int luaopen_dbgmodule(lua_State *L)
{
	luaL_newmetatable(L, "dbgmodule.metatable");

	for (const luaL_Reg *l = dbgmodule_func; l->name != NULL; l++) {
		lua_pushstring(L, l->name);
		lua_pushcfunction(L, l->func);
		lua_settable(L, -3);
	}

	lua_newtable(L);
	luaL_setfuncs(L, dbgmodule_lib, 0);
	lua_pushvalue(L, -1);
	lua_setglobal(L, "dbgmodule");
	lua_remove(L, -2);
	return 1;
}

/************************************************************************/
/*                        dbgthread                                     */
/************************************************************************/


typedef struct _DBG_THREAD {
	ULONG ThreadDbgId;
	ULONG ThreadId;
} DBG_THREAD;

static int dbgthread_new(lua_State *L)
{
	ULONG dbgid = (ULONG)luaL_checkinteger(L, 1);
	ULONG id = 0;

	ULONG thread_count = 0;
	if (FAILED(g_Ext->m_System->GetNumberThreads(&thread_count))) {
		lua_pushnil(L);
		return 1;
	}

	std::vector<ULONG> dbgids, ids;
	dbgids.resize(thread_count);
	ids.resize(thread_count);

	if (FAILED(g_Ext->m_System->GetThreadIdsByIndex(0, thread_count, dbgids.data(), ids.data()))) {
		lua_pushnil(L);
		return 1;
	}

	for (ULONG i = 0; i < thread_count; i++) {
		if (dbgids[i] == dbgid) {
			id = ids[i];
			break;
		}
	}

	if (id == 0) {
		lua_pushnil(L);
		return 1;
	}

	DBG_THREAD *m = (DBG_THREAD *)lua_newuserdata(L, sizeof(DBG_THREAD));

	luaL_getmetatable(L, "dbgthread.metatable");
	lua_setmetatable(L, -2);

	m->ThreadDbgId = dbgid;
	m->ThreadId = id;

	return 1;
}

static DBG_THREAD *dbgthread_check(lua_State *L)
{
	void *ud = luaL_checkudata(L, 1, "dbgthread.metatable");
	luaL_argcheck(L, ud != NULL, 1, "`dbgthread' expected");
	return (DBG_THREAD *)ud;
}

static int dbgthread_sysid(lua_State *L)
{
	DBG_THREAD *m = dbgthread_check(L);
	lua_pushinteger(L, m->ThreadId);
	return 1;
}

static int dbgthread_dbgid(lua_State *L)
{
	DBG_THREAD *m = dbgthread_check(L);
	lua_pushinteger(L, m->ThreadDbgId);
	return 1;
}

static int dbgthread_isvalid(lua_State *L)
{
	DBG_THREAD *m = dbgthread_check(L);
	ULONG id = 0;
	if (FAILED(g_Ext->m_System->GetThreadIdBySystemId(m->ThreadId, &id))) {
		lua_pushboolean(L, FALSE);
		return 1;
	}

	lua_pushboolean(L, m->ThreadDbgId == id);
	return 1;
}

static int dbgthread_getteb(lua_State *L)
{
	DBG_THREAD *m = dbgthread_check(L);
	ULONG64 offset = 0;

	ULONG current_dtid = 0;
	g_Ext->m_System->GetCurrentThreadId(&current_dtid);
	g_Ext->m_System->SetCurrentThreadId(m->ThreadDbgId);

	HRESULT hr = g_Ext->m_System2->GetImplicitThreadDataOffset(&offset);
	g_Ext->m_System->SetCurrentThreadId(current_dtid);

	if (FAILED(hr)) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushinteger(L, offset);
	return 1;
}

static int dbgthread_currentid(lua_State *L)
{
	ULONG id = 0;
	if (FAILED(g_Ext->m_System->GetCurrentThreadId(&id))) {
		lua_pushnil(L);
		return 1;
	}
	lua_pushinteger(L, id);
	return 1;
}

__inline void lua_pushtable(lua_State* L , const char* key , ULONG64 value) {
	lua_pushstring(L, key);
	lua_pushinteger(L, value);
	lua_settable(L, -3);
}

static int dbgthread_stack(lua_State *L)
{
	DBG_THREAD *m = dbgthread_check(L);

	ULONG current_dtid = 0;
	g_Ext->m_System->GetCurrentThreadId(&current_dtid);
	g_Ext->m_System->SetCurrentThreadId(m->ThreadDbgId);

	std::vector<DEBUG_STACK_FRAME> stack_frames;
	ULONG fill_count = 0;
	stack_frames.resize(0x1000);
	g_Ext->m_Control->GetStackTrace(0, 0, 0, stack_frames.data(), 0x1000, &fill_count);
	g_Ext->m_System->SetCurrentThreadId(current_dtid);
	if (fill_count == 0) {
		lua_pushnil(L);
		return 1;
	}

	lua_newtable(L);
	for (ULONG i = 0; i < fill_count; i++) {
		lua_pushinteger(L, i);
		lua_newtable(L);
		lua_pushtable(L, "InstructionOffset", stack_frames[i].InstructionOffset);
		lua_pushtable(L, "ReturnOffset", stack_frames[i].ReturnOffset);
		lua_pushtable(L, "FrameOffset", stack_frames[i].FrameOffset);
		lua_pushtable(L, "StackOffset", stack_frames[i].StackOffset);
		lua_pushtable(L, "FuncTableEntry", stack_frames[i].FuncTableEntry);
		lua_pushtable(L, "Virtual", stack_frames[i].Virtual);
		lua_pushtable(L, "FrameNumber", stack_frames[i].FrameNumber);
		lua_pushtable(L, "Params0", stack_frames[i].Params[0]);
		lua_pushtable(L, "Params1", stack_frames[i].Params[1]);
		lua_pushtable(L, "Params2", stack_frames[i].Params[2]);
		lua_pushtable(L, "Params3", stack_frames[i].Params[3]);
		lua_settable(L, -3);
	}

	return 1;
}

static int dbgthread_setcurrentid(lua_State *L)
{
	ULONG id = (ULONG)luaL_checkinteger(L, 1);
	g_Ext->m_System->SetCurrentThreadId(id);
	return 0;
}

static const struct luaL_Reg dbgthread_lib [] = {
	{"new", dbgthread_new},
	{"currentid", dbgthread_currentid},
	{"setcurrentid", dbgthread_setcurrentid},
	{NULL, NULL}
};

static int dbgthread___index(lua_State *L)
{
	const char *member_name = luaL_checkstring(L, -1);

	lua_getmetatable(L, -2);
	lua_pushstring(L, member_name);
	lua_rawget(L,-2);
	lua_remove(L,-2);
	if (lua_isfunction(L, -1))
	{
		lua_remove(L, -2);
		return 1;
	}
	lua_pushnil(L);
	return 1;
}

static const struct luaL_Reg dbgthread_func[] = {
	{ "__index", dbgthread___index },
	{ "addr", dbgthread_dbgid },
	{ "name", dbgthread_sysid },
	{ "isvalid", dbgthread_isvalid },
	{ "stack", dbgthread_stack },
	{ "getteb", dbgthread_getteb },
	{ NULL, NULL }
};

int luaopen_dbgthread(lua_State *L)
{
	luaL_newmetatable(L, "dbgthread.metatable");

	for (const luaL_Reg *l = dbgthread_func; l->name != NULL; l++) {
		lua_pushstring(L, l->name);
		lua_pushcfunction(L, l->func);
		lua_settable(L, -3);
	}

	lua_newtable(L);
	luaL_setfuncs(L, dbgthread_lib, 0);
	lua_pushvalue(L, -1);
	lua_setglobal(L, "dbgthread");
	lua_remove(L, -2);
	return 1;
}

/************************************************************************/
/*                        dbgtype                                       */
/************************************************************************/

enum SymTagEnum {
	SymTagNull,
	SymTagExe,
	SymTagCompiland,
	SymTagCompilandDetails,
	SymTagCompilandEnv,
	SymTagFunction,
	SymTagBlock,
	SymTagData,
	SymTagAnnotation,
	SymTagLabel,
	SymTagPublicSymbol,
	SymTagUDT,
	SymTagEnum,
	SymTagFunctionType,
	SymTagPointerType,
	SymTagArrayType,
	SymTagBaseType,
	SymTagTypedef,
	SymTagBaseClass,
	SymTagFriend,
	SymTagFunctionArgType,
	SymTagFuncDebugStart,
	SymTagFuncDebugEnd,
	SymTagUsingNamespace,
	SymTagVTableShape,
	SymTagVTable,
	SymTagCustom,
	SymTagThunk,
	SymTagCustomType,
	SymTagManagedType,
	SymTagDimension,
	SymTagCallSite,
	SymTagInlineSite,
	SymTagBaseInterface,
	SymTagVectorType,
	SymTagMatrixType,
	SymTagHLSLType
};

typedef struct _DBG_TYPE {
	CHAR TypeName[1024];
	CHAR ModuleName[1024];
	ULONG64 ModuleAddr;
	ULONG TypeId;
	ULONG64 Address;
} DBG_TYPE;


static int dbgtype_new(lua_State *L)
{
	const char *type_name = luaL_checkstring(L, 1);
	ULONG64 addr = luaL_checkinteger(L, 2);
	ULONG type_id = 0;

	char type_name_str[2048];
	if (strlen(type_name) >= sizeof(type_name_str)) {
		luaL_argerror(L, 1, "type name is too long");
		return 0;
	}
	strcpy_s(type_name_str, type_name);

	char *pos = strchr(type_name_str, '!');
	luaL_argcheck(L, pos != NULL, 1, "`module!symbol' expected");
	if (pos == NULL) {
		lua_pushnil(L);
		return 1;
	}

	*pos = 0;
	pos++;

	if (FAILED(g_Ext->m_Symbols->GetTypeId(0, type_name, &type_id))) {
		lua_pushnil(L);
		return 1;
	}

	ULONG index = 0;
	ULONG64 module_addr = 0;
	if (FAILED(g_Ext->m_Symbols->GetModuleByModuleName(type_name_str, 0, &index, &module_addr)) || module_addr == 0) {
		lua_pushnil(L);
		return 1;
	}

	DBG_TYPE *m = (DBG_TYPE *)lua_newuserdata(L, sizeof(DBG_TYPE));

	luaL_getmetatable(L, "dbgtype.metatable");
	lua_setmetatable(L, -2);

	m->Address = addr;
	m->TypeId = type_id;
	m->ModuleAddr = module_addr;
	if (!CopyLuaString(m->TypeName, sizeof(m->TypeName), pos) ||
		!CopyLuaString(m->ModuleName, sizeof(m->ModuleName), type_name_str)) {
		lua_pop(L, 1);
		lua_pushnil(L);
	}

	return 1;
}

static DBG_TYPE *dbgtype_check (lua_State *L)
{
	void *ud = luaL_checkudata(L, 1, "dbgtype.metatable");
	luaL_argcheck(L, ud != NULL, 1, "`dbgtype' expected");
	return (DBG_TYPE *)ud;
}

static int dbgtype_getname(lua_State *L)
{
	DBG_TYPE *m = dbgtype_check(L);
	char module_type_name[2048];
	sprintf_s(module_type_name, "%s!%s", m->ModuleName, m->TypeName);
	lua_pushstring(L, module_type_name);
	return 1;
}

static int dbgtype_getaddr(lua_State *L)
{
	DBG_TYPE *m = dbgtype_check(L);
	lua_pushinteger(L, m->Address);
	return 1;
}

static int dbgtype_getsize(lua_State *L)
{
	DBG_TYPE *m = dbgtype_check(L);
	ULONG type_size = 0;
	if (FAILED(g_Ext->m_Symbols->GetTypeSize(m->ModuleAddr, m->TypeId, &type_size))) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushinteger(L, type_size);
	return 1;
}

static int dbgtype_getfieldoffset(lua_State *L)
{
	DBG_TYPE *m = dbgtype_check(L);
	const char *name = luaL_checkstring(L, 2);

	ULONG offset = 0;
	if (FAILED(g_Ext->m_Symbols->GetFieldOffset(m->ModuleAddr, m->TypeId, name, &offset))) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushinteger(L, offset);
	return 1;
}

static int dbgtype_getderef(lua_State *L)
{
	DBG_TYPE *m = dbgtype_check(L);

	ExtRemoteTyped type_obj;
	type_obj.Set(FALSE, m->ModuleAddr, m->TypeId, m->Address);
	char type_buffer[1024];
	ExtRemoteTyped field = *type_obj;
	if (FAILED(g_Ext->m_Symbols3->GetTypeName(m->ModuleAddr, field.m_Typed.TypeId, type_buffer, 1024, NULL))) {
		lua_pushnil(L);
		return 1;
	}

	DBG_TYPE *new_m = (DBG_TYPE *)lua_newuserdata(L, sizeof(DBG_TYPE));

	luaL_getmetatable(L, "dbgtype.metatable");
	lua_setmetatable(L, -2);

	ExtRemoteData data(m->Address, g_Ext->m_PtrSize);
	new_m->Address = data.GetPtr();
	new_m->TypeId = field.m_Typed.TypeId;
	new_m->ModuleAddr = m->ModuleAddr;
	if (!CopyLuaString(new_m->TypeName, sizeof(new_m->TypeName), type_buffer) ||
		!CopyLuaString(new_m->ModuleName, sizeof(new_m->ModuleName), m->ModuleName)) {
		lua_pop(L, 1);
		lua_pushnil(L);
		return 1;
	}

	return 1;
}

static int dbgtype_getfieldtype(lua_State *L)
{

	DBG_TYPE *m = dbgtype_check(L);
	const char *name = luaL_checkstring(L, 2);

	ULONG type_id = 0;
	if (FAILED(g_Ext->m_Symbols3->GetFieldTypeAndOffset(m->ModuleAddr, m->TypeId, name, &type_id, NULL))) {
		lua_pushnil(L);
		return 1;
	}

	char type_buffer[1024];
	if (FAILED(g_Ext->m_Symbols3->GetTypeName(m->ModuleAddr, type_id, type_buffer, 1024, NULL))) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushstring(L, type_buffer);

	return 1;
}

static const struct luaL_Reg dbgtype_lib [] = {
	{"new", dbgtype_new},
	{NULL, NULL}
};

static int dbgtype___index(lua_State *L)
{
	const char *name = luaL_checkstring(L, -1);

	lua_getmetatable(L, -2);
	lua_pushstring(L, name);
	lua_rawget(L,-2);
	lua_remove(L,-2);
	if (lua_isfunction(L, -1))
	{
		lua_remove(L, -2);
		return 1;
	}

	DBG_TYPE *m = dbgtype_check(L);
	ExtRemoteTyped type_obj;
	type_obj.Set(FALSE, m->ModuleAddr, m->TypeId, m->Address);
	if (type_obj.m_Typed.Tag == SymTagArrayType) {
		ExtRemoteTyped array_item = type_obj.ArrayElement(atoi(name));

		char type_buffer[1024];
		if (FAILED(g_Ext->m_Symbols3->GetTypeName(m->ModuleAddr, array_item.m_Typed.TypeId, type_buffer, 1024, NULL))) {
			lua_pushnil(L);
			return 1;
		}

		if (array_item.m_Typed.Tag == SymTagBaseType) {
			lua_pushstring(L, array_item.GetSimpleValue());
			return 1;
		}

		DBG_TYPE *new_m = (DBG_TYPE *)lua_newuserdata(L, sizeof(DBG_TYPE));

		luaL_getmetatable(L, "dbgtype.metatable");
		lua_setmetatable(L, -2);

		new_m->Address = array_item.m_Offset;
		new_m->TypeId = array_item.m_Typed.TypeId;
		new_m->ModuleAddr = m->ModuleAddr;
		strncpy_s(new_m->TypeName, type_buffer, _TRUNCATE);
		strncpy_s(new_m->ModuleName, m->ModuleName, _TRUNCATE);

		return 1;
	}

	ULONG type_id = 0;
	if (FAILED(g_Ext->m_Symbols3->GetFieldTypeAndOffset(m->ModuleAddr, m->TypeId, name, &type_id, NULL))) {
		lua_pushnil(L);
		return 1;
	}

	char type_buffer[1024];
	if (FAILED(g_Ext->m_Symbols3->GetTypeName(m->ModuleAddr, type_id, type_buffer, 1024, NULL))) {
		lua_pushnil(L);
		return 1;
	}

	ExtRemoteTyped field = type_obj.Field(name);

	if (field.m_Typed.Tag == SymTagPointerType) {
		DBG_TYPE *new_m = (DBG_TYPE *)lua_newuserdata(L, sizeof(DBG_TYPE));

		luaL_getmetatable(L, "dbgtype.metatable");
		lua_setmetatable(L, -2);

		new_m->Address = field.m_Offset;
		new_m->TypeId = field.m_Typed.TypeId;
		new_m->ModuleAddr = m->ModuleAddr;
		strncpy_s(new_m->TypeName, type_buffer, _TRUNCATE);
		strncpy_s(new_m->ModuleName, m->ModuleName, _TRUNCATE);

	}
	else if (field.m_Typed.Tag == SymTagBaseType) {
		lua_pushstring(L, field.GetSimpleValue());
	}
	else if (field.m_Typed.Tag == SymTagUDT || field.m_Typed.Tag == SymTagArrayType) {
		DBG_TYPE *new_m = (DBG_TYPE *)lua_newuserdata(L, sizeof(DBG_TYPE));

		luaL_getmetatable(L, "dbgtype.metatable");
		lua_setmetatable(L, -2);

		new_m->Address = field.m_Offset;
		new_m->TypeId = field.m_Typed.TypeId;
		new_m->ModuleAddr = m->ModuleAddr;
		strncpy_s(new_m->TypeName, type_buffer, _TRUNCATE);
		strncpy_s(new_m->ModuleName, m->ModuleName, _TRUNCATE);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

static const struct luaL_Reg dbgtype_func[] = {
	{ "__index", dbgtype___index },
	{ "addr", dbgtype_getaddr },
	{ "name", dbgtype_getname },
	{ "size", dbgtype_getsize },
	{ "deref", dbgtype_getderef },
	{ "fieldoffset", dbgtype_getfieldoffset },
	{ "fieldtype", dbgtype_getfieldtype },
	{ NULL, NULL }
};

int luaopen_dbgtype(lua_State *L)
{
	luaL_newmetatable(L, "dbgtype.metatable");

	for (const luaL_Reg *l = dbgtype_func; l->name != NULL; l++) {
		lua_pushstring(L, l->name);
		lua_pushcfunction(L, l->func);
		lua_settable(L, -3);
	}

	lua_newtable(L);
	luaL_setfuncs(L, dbgtype_lib, 0);
	lua_pushvalue(L, -1);
	lua_setglobal(L, "dbgtype");
	lua_remove(L, -2);
	return 1;
}


/************************************************************************/
/*                          dbgreg                                      */
/************************************************************************/

typedef struct _DBG_REG {
	ULONG RegIndex;
	CHAR RegName[1024];
} DBG_REG;

static int dbgreg_new(lua_State *L)
{
	const char *reg_name = luaL_checkstring(L, 1);
	ULONG index = 0;
	if (FAILED(g_Ext->m_Registers->GetIndexByName(reg_name, &index))) {
		lua_pushnil(L);
		return 1;
	}

	DBG_REG *m = (DBG_REG *)lua_newuserdata(L, sizeof(DBG_REG));

	luaL_getmetatable(L, "dbgreg.metatable");
	lua_setmetatable(L, -2);

	m->RegIndex = index;
	if (!CopyLuaString(m->RegName, sizeof(m->RegName), reg_name)) {
		lua_pop(L, 1);
		lua_pushnil(L);
	}

	return 1;
}

static DBG_REG *dbgreg_check(lua_State *L)
{
	void *ud = luaL_checkudata(L, 1, "dbgreg.metatable");
	luaL_argcheck(L, ud != NULL, 1, "`dbgreg' expected");
	return (DBG_REG *)ud;
}

static int dbgreg_getname(lua_State *L)
{
	DBG_REG *m = dbgreg_check(L);
	lua_pushstring(L, m->RegName);
	return 1;
}

static int dbgreg_getindex(lua_State *L)
{
	DBG_REG *m = dbgreg_check(L);
	lua_pushinteger(L, m->RegIndex);
	return 1;
}

static const struct luaL_Reg dbgreg_lib[] = {
	{ "new", dbgreg_new },
	{ NULL, NULL }
};

static int dbgreg___index(lua_State *L)
{
	const char *member_name = luaL_checkstring(L, -1);

	lua_getmetatable(L, -2);
	lua_pushstring(L, member_name);
	lua_rawget(L, -2);
	lua_remove(L, -2);
	if (lua_isfunction(L, -1))
	{
		lua_remove(L, -2);
		return 1;
	}

	lua_pushnil(L);
	return 1;
}

static int dbgreg_get(lua_State *L)
{
	DBG_REG *m = dbgreg_check(L);
	DEBUG_VALUE value = {0};
	if (FAILED(g_Ext->m_Registers->GetValue(m->RegIndex, &value))) {
		lua_pushnil(L);
		return 1;
	}

	if (value.Type == DEBUG_VALUE_INT8) {
		lua_pushinteger(L, value.I8);
	}
	else if (value.Type == DEBUG_VALUE_INT16) {
		lua_pushinteger(L, value.I16);
	}
	else if (value.Type == DEBUG_VALUE_INT32) {
		lua_pushinteger(L, value.I32);
	}
	else if (value.Type == DEBUG_VALUE_INT64) {
		lua_pushinteger(L, value.I64);
	}
	else if (value.Type == DEBUG_VALUE_FLOAT32) {
		lua_pushnumber(L, value.F32);
	}
	else if (value.Type == DEBUG_VALUE_FLOAT64) {
		lua_pushnumber(L, value.F64);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

static int dbgreg_set(lua_State *L)
{
	DBG_REG *m = dbgreg_check(L);
	DEBUG_REGISTER_DESCRIPTION des= { 0 };
	if (FAILED(g_Ext->m_Registers->GetDescription(m->RegIndex, NULL, 0, NULL, &des))) {
		return 0;
	}

	DEBUG_VALUE value = { 0 };
	value.Type = des.Type;
	if (value.Type == DEBUG_VALUE_INT8) {
		ULONG64 reg_value = luaL_checkinteger(L, 2);
		value.I8 = (UCHAR)reg_value;
		g_Ext->m_Registers->SetValue(m->RegIndex, &value);
	}
	else if (value.Type == DEBUG_VALUE_INT16) {
		ULONG64 reg_value = luaL_checkinteger(L, 2);
		value.I16 = (USHORT)reg_value;
		g_Ext->m_Registers->SetValue(m->RegIndex, &value);
	}
	else if (value.Type == DEBUG_VALUE_INT32) {
		ULONG64 reg_value = luaL_checkinteger(L, 2);
		value.I32 = (ULONG)reg_value;
		g_Ext->m_Registers->SetValue(m->RegIndex, &value);
	}
	else if (value.Type == DEBUG_VALUE_INT64) {
		ULONG64 reg_value = luaL_checkinteger(L, 2);
		value.I64 = reg_value;
		g_Ext->m_Registers->SetValue(m->RegIndex, &value);
	}
	else if (value.Type == DEBUG_VALUE_FLOAT32) {
		double reg_value = luaL_checknumber(L, 2);
		value.F32 = (float)reg_value;
		g_Ext->m_Registers->SetValue(m->RegIndex, &value);
	}
	else if (value.Type == DEBUG_VALUE_FLOAT64) {
		double reg_value = luaL_checknumber(L, 2);
		value.F64 = reg_value;
		g_Ext->m_Registers->SetValue(m->RegIndex, &value);
	}

	return 0;
}

static const struct luaL_Reg dbgreg_func[] = {
	{ "__index", dbgreg___index },
	{ "get", dbgreg_get },
	{ "set", dbgreg_set },
	{ "index", dbgreg_getindex },
	{ "name", dbgreg_getname },
	{ NULL, NULL }
};

int luaopen_dbgreg(lua_State *L)
{
	luaL_newmetatable(L, "dbgreg.metatable");

	for (const luaL_Reg *l = dbgreg_func; l->name != NULL; l++) {
		lua_pushstring(L, l->name);
		lua_pushcfunction(L, l->func);
		lua_settable(L, -3);
	}

	lua_newtable(L);
	luaL_setfuncs(L, dbgreg_lib, 0);
	lua_pushvalue(L, -1);
	lua_setglobal(L, "dbgreg");
	lua_remove(L, -2);
	return 1;
}


/************************************************************************/
/*                        dbgmem                                        */
/************************************************************************/


typedef struct _DBG_MEM {
	ULONG64 Offset;
	ULONG Size;
	ULONG CachedSize;
	UCHAR Buffer[1];
} DBG_MEM;

static const lua_Integer DBG_MEM_MAX_SIZE = 64 * 1024 * 1024;

static int dbgmem_new(lua_State *L)
{
	ULONG64 offset = (ULONG64)luaL_checkinteger(L, 1);
	lua_Integer requested_size = luaL_checkinteger(L, 2);
	if (requested_size <= 0 || requested_size > DBG_MEM_MAX_SIZE) {
		lua_pushnil(L);
		return 1;
	}
	ULONG mem_size = (ULONG)requested_size;

	UCHAR *buffer = (UCHAR *)malloc(mem_size);
	if (buffer == NULL) {
		lua_pushnil(L);
		return 1;
	}

	ULONG cached_size = 0;
	if (FAILED(g_Ext->m_Data->ReadVirtual(offset, buffer, mem_size, &cached_size)) || cached_size == 0) {
		free(buffer);
		lua_pushnil(L);
		return 1;
	}

	DBG_MEM *m = (DBG_MEM *)lua_newuserdata(L, sizeof(DBG_MEM) + cached_size - 1);

	luaL_getmetatable(L, "dbgmem.metatable");
	lua_setmetatable(L, -2);

	m->Offset = offset;
	m->Size = mem_size;
	m->CachedSize = cached_size;
	CopyMemory(m->Buffer, buffer, cached_size);

	free(buffer);

	return 1;
}

static DBG_MEM *dbgmem_check(lua_State *L)
{
	void *ud = luaL_checkudata(L, 1, "dbgmem.metatable");
	luaL_argcheck(L, ud != NULL, 1, "`dbgmem' expected");
	return (DBG_MEM *)ud;
}

static int dbgmem_getoffset(lua_State *L)
{
	DBG_MEM *m = dbgmem_check(L);
	lua_pushinteger(L, m->Offset);
	return 1;
}

static int dbgmem_getsize(lua_State *L)
{
	DBG_MEM *m = dbgmem_check(L);
	lua_pushinteger(L, m->Size);
	return 1;
}

static int dbgmem_getcachedsize(lua_State *L)
{
	DBG_MEM *m = dbgmem_check(L);
	lua_pushinteger(L, m->CachedSize);
	return 1;
}

static int dbgmem_getstring(lua_State *L)
{
	DBG_MEM *m = dbgmem_check(L);
	lua_pushlstring(L, (char *)m->Buffer, m->CachedSize);
	return 1;
}

static int dbgmem_tohexstring(lua_State *L)
{
	DBG_MEM *m = dbgmem_check(L);

	int hex_str_len = AtlHexEncodeGetRequiredLength(m->CachedSize);
	CStringA hex_str;

	int encode_length = hex_str_len;
	AtlHexEncode(m->Buffer, m->CachedSize, hex_str.GetBufferSetLength(hex_str_len), &encode_length);
	hex_str.ReleaseBuffer(encode_length);

	lua_pushstring(L, hex_str.GetString());

	return 1;
}

static int dbgmem_fromhexstring(lua_State *L)
{
	DBG_MEM *m = dbgmem_check(L);
	const char* hex_str = luaL_checkstring(L, 2);

	size_t source_length = strlen(hex_str);
	if (source_length > INT_MAX) {
		luaL_argerror(L, 2, "hex string is too long");
		return 0;
	}
	int hex_buffer_len = AtlHexDecodeGetRequiredLength((int)source_length);
	if (hex_buffer_len <= 0 || (ULONG)hex_buffer_len > m->CachedSize) {
		luaL_argerror(L, 2, "hex string does not fit in memory object");
		return 0;
	}

	int decode_length = hex_buffer_len;
	if (!AtlHexDecode(hex_str, (int)source_length, m->Buffer, &decode_length) || decode_length <= 0) {
		luaL_argerror(L, 2, "invalid hex string");
		return 0;
	}
	ULONG written = 0;
	if (FAILED(g_Ext->m_Data->WriteVirtual(m->Offset, (PVOID)m->Buffer, (ULONG)decode_length, &written)) ||
		written != (ULONG)decode_length) {
		luaL_argerror(L, 2, "failed to write debuggee memory");
		return 0;
	}

	return 0;
}

static int dbgmem_setstring(lua_State *L)
{
	DBG_MEM *m = dbgmem_check(L);
	const char* buffer = luaL_checkstring(L, 2);
	lua_Unsigned raw_size = lua_rawlen(L, 2);
	if (raw_size > 0xFFFFFFFFULL || raw_size > m->CachedSize) {
		luaL_argerror(L, 2, "string does not fit in memory object");
		return 0;
	}
	ULONG mem_size = static_cast<ULONG>(raw_size);

	ULONG cached_size = 0;
	if (FAILED(g_Ext->m_Data->WriteVirtual(m->Offset, (PVOID)buffer, mem_size, &cached_size)) ||
		cached_size != mem_size) {
		luaL_argerror(L, 2, "failed to write debuggee memory");
		return 0;
	}
	CopyMemory(m->Buffer, buffer, mem_size);
	return 0;
}

static const struct luaL_Reg dbgmem_lib [] = {
	{"new", dbgmem_new},
	{NULL, NULL}
};

static int dbgmem___index(lua_State *L)
{
	const char *member_name = luaL_checkstring(L, -1);

	lua_getmetatable(L, -2);
	lua_pushstring(L, member_name);
	lua_rawget(L,-2);
	lua_remove(L,-2);
	if (lua_isfunction(L, -1))
	{
		lua_remove(L, -2);
		return 1;
	}
	DBG_MEM *m = dbgmem_check(L);

	char *end = NULL;
	unsigned long index = strtoul(member_name, &end, 10);
	if (end == member_name || *end != '\0' || index >= m->CachedSize) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushinteger(L, m->Buffer[index]);
	return 1;
}

static int dbgmem___newindex(lua_State *L)
{
	const char *member_name = luaL_checkstring(L, -2);
	UCHAR data = (UCHAR)luaL_checkinteger(L, -1);
	DBG_MEM *m = dbgmem_check(L);

	char *end = NULL;
	unsigned long index = strtoul(member_name, &end, 10);
	if (end == member_name || *end != '\0' || index >= m->CachedSize) {
		return 0;
	}
	m->Buffer[index] = data;
	g_Ext->m_Data->WriteVirtual(m->Offset + index, &m->Buffer[index], 1, NULL);
	return 0;
}

static int dbgmem_update(lua_State *L)
{
	DBG_MEM *m = dbgmem_check(L);
	ULONG read_size = 0;
	if (FAILED(g_Ext->m_Data->ReadVirtual(m->Offset, m->Buffer, m->CachedSize, &read_size))) {
		luaL_error(L, "failed to read debuggee memory");
	}
	return 0;
}

static const struct luaL_Reg dbgmem_func[] = {
	{ "__index", dbgmem___index },
	{ "__newindex", dbgmem___newindex },
	{ "offset", dbgmem_getoffset },
	{ "size", dbgmem_getsize },
	{ "cachedsize", dbgmem_getcachedsize },
	{ "getstring", dbgmem_getstring },
	{ "setstring", dbgmem_setstring },
	{ "update", dbgmem_update },
	{ "tohexstring", dbgmem_tohexstring },
	{ "fromhexstring", dbgmem_fromhexstring },
	{ NULL, NULL }
};

int luaopen_dbgmem(lua_State *L)
{
	luaL_newmetatable(L, "dbgmem.metatable");

	for (const luaL_Reg *l = dbgmem_func; l->name != NULL; l++) {
		lua_pushstring(L, l->name);
		lua_pushcfunction(L, l->func);
		lua_settable(L, -3);
	}

	lua_newtable(L);
	luaL_setfuncs(L, dbgmem_lib, 0);
	lua_pushvalue(L, -1);
	lua_setglobal(L, "dbgmem");
	lua_remove(L, -2);
	return 1;
}


/************************************************************************/
/*                        dbg                                           */
/************************************************************************/

static int exec(lua_State* L)
{
	const char* cmd = luaL_checkstring(L, 1);
	g_Ext->m_Control->Execute(DEBUG_OUTCTL_ALL_CLIENTS |
		DEBUG_OUTCTL_OVERRIDE_MASK |
		DEBUG_OUTCTL_NOT_LOGGED,
		cmd,
		DEBUG_EXECUTE_DEFAULT);

	return 0;
}

static int exec_tostring(lua_State* L)
{
	const char* cmd = luaL_checkstring(L, 1);
	ExtCaptureOutputA capture_exec;
	capture_exec.Execute(cmd);
	LPCSTR out_text = capture_exec.GetTextNonNull();

	lua_pushstring(L, out_text);

	return 1;
}

static int readbyte(lua_State* L)
{
	BOOL ret = FALSE;
	ULONG data = 0;
	ULONG return_length = 0;
	ULONG64 offset = luaL_checkinteger(L, 1);
	HRESULT hr = g_Ext->m_Data->ReadVirtual((ULONG64)offset, &data, 1, &return_length);
	if (SUCCEEDED(hr)) {
		ret = TRUE;
	}

	if (ret) {
		lua_pushinteger(L, data);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

static int readword(lua_State* L)
{
	BOOL ret = FALSE;
	ULONG data = 0;
	ULONG return_length = 0;
	ULONG64 offset = luaL_checkinteger(L, 1);
	HRESULT hr = g_Ext->m_Data->ReadVirtual((ULONG64)offset, &data, 2, &return_length);
	if (SUCCEEDED(hr)) {
		ret = TRUE;
	}

	if (ret) {
		lua_pushinteger(L, data);
	}
	else {
		lua_pushnil(L);
	}
	return 1;
}

static int readdword(lua_State* L)
{
	BOOL ret = FALSE;
	ULONG data = 0;
	ULONG return_length = 0;
	ULONG64 offset = luaL_checkinteger(L, 1);
	HRESULT hr = g_Ext->m_Data->ReadVirtual((ULONG64)offset, &data, 4, &return_length);
	if (SUCCEEDED(hr)) {
		ret = TRUE;
	}

	if (ret) {
		lua_pushinteger(L, data);
	}
	else {
		lua_pushnil(L);
	}
	return 1;
}

static int readqword(lua_State* L)
{
	BOOL ret = FALSE;
	ULONG64 data = 0;
	ULONG return_length = 0;
	ULONG64 offset = luaL_checkinteger(L, 1);
	HRESULT hr = g_Ext->m_Data->ReadVirtual((ULONG64)offset, &data, 8, &return_length);
	if (SUCCEEDED(hr)) {
		ret = TRUE;
	}

	if (ret) {
		lua_pushinteger(L, data);
	}
	else {
		lua_pushnil(L);
	}
	return 1;
}

static int writebyte(lua_State* L)
{
	ULONG return_length = 0;
	ULONG64 offset = luaL_checkinteger(L, 1);
	ULONG64 data = luaL_checkinteger(L, 2);
	g_Ext->m_Data->WriteVirtual((ULONG64)offset, &data, 1, &return_length);
	return 0;
}

static int writeword(lua_State* L)
{
	ULONG return_length = 0;
	ULONG64 offset = luaL_checkinteger(L, 1);
	ULONG64 data = luaL_checkinteger(L, 2);
	g_Ext->m_Data->WriteVirtual((ULONG64)offset, &data, 2, &return_length);
	return 0;
}

static int writedword(lua_State* L)
{
	ULONG return_length = 0;
	ULONG64 offset = luaL_checkinteger(L, 1);
	ULONG64 data = luaL_checkinteger(L, 2);
	g_Ext->m_Data->WriteVirtual((ULONG64)offset, &data, 4, &return_length);
	return 0;
}

static int writeqword(lua_State* L)
{
	ULONG return_length = 0;
	ULONG64 offset = luaL_checkinteger(L, 1);
	ULONG64 data = luaL_checkinteger(L, 2);
	g_Ext->m_Data->WriteVirtual((ULONG64)offset, &data, 8, &return_length);
	return 0;
}

static int readwidestrng(lua_State* L)
{
	CStringW unicode_string;
	WCHAR temp_char;
	ULONG return_length;
	ULONG64 offset = luaL_checkinteger(L, 1);
	for (INT i = 0; i < 0x1000; i++) {
		HRESULT hr = g_Ext->m_Data->ReadVirtual((ULONG64)(offset + i * sizeof(WCHAR)),
			&temp_char, sizeof(WCHAR), &return_length);
		if (FAILED(hr) || temp_char == L'\0') {
			break;
		}
		unicode_string += temp_char;
	}

	int utf8_length = WideCharToMultiByte(CP_UTF8, 0, unicode_string.GetString(),
		unicode_string.GetLength(), NULL, 0, NULL, NULL);
	if (utf8_length <= 0) {
		lua_pushliteral(L, "");
		return 1;
	}
	std::string utf8(static_cast<size_t>(utf8_length), '\0');
	WideCharToMultiByte(CP_UTF8, 0, unicode_string.GetString(), unicode_string.GetLength(),
		&utf8[0], utf8_length, NULL, NULL);
	lua_pushlstring(L, utf8.data(), utf8.size());
	return 1;
}

static int readstring(lua_State* L)
{
	CStringA ascii_string;
	CHAR temp_char;
	ULONG return_length;
	ULONG64 offset = luaL_checkinteger(L, 1);
	for (INT i = 0; i < 1024; i++) {
		HRESULT hr = g_Ext->m_Data->ReadVirtual((ULONG64)(offset + i * sizeof(CHAR)),
			&temp_char, sizeof(CHAR), &return_length);
		if (FAILED(hr) || temp_char == '\0') {
			break;
		}
		ascii_string += temp_char;
	}

	lua_pushstring(L, ascii_string);
	return 1;
}

static int wait(lua_State* L)
{
	UNREFERENCED_PARAMETER(L);
	g_Ext->m_Control->WaitForEvent(0, INFINITE);
	return 0;
}

static int evalmasm(lua_State* L)
{
	BOOL ret = FALSE;
	ULONG64 eval_ret = 0;
	const char* string = luaL_checkstring(L, 1);
	DEBUG_VALUE debug_value = { 0 };
	ULONG old_type;
	ULONG return_index;
	g_Ext->m_Control3->GetExpressionSyntax(&old_type);
	g_Ext->m_Control3->SetExpressionSyntax(DEBUG_EXPR_MASM);

	HRESULT hr = g_Ext->m_Control3->Evaluate(string, DEBUG_VALUE_INT64, &debug_value, &return_index);
	if (SUCCEEDED(hr)) {
		if (debug_value.Type == DEBUG_VALUE_INT8) {
			eval_ret = debug_value.I8;
			ret = TRUE;
		}
		else if (debug_value.Type == DEBUG_VALUE_INT16) {
			eval_ret = debug_value.I16;
			ret = TRUE;
		}
		else if (debug_value.Type == DEBUG_VALUE_INT32) {
			eval_ret = debug_value.I32;
			ret = TRUE;
		}
		else if (debug_value.Type == DEBUG_VALUE_INT64) {
			eval_ret = debug_value.I64;
			ret = TRUE;
		}
		else {
			g_Ext->Err("Lua dose not support this value.\n");
		}
	}
	else {
		g_Ext->Err("Cannot evaluate value.\n");
	}

	g_Ext->m_Control3->SetExpressionSyntax(old_type);

	if (ret) {
		lua_pushinteger(L, eval_ret);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

static int evalcpp(lua_State* L)
{
	BOOL ret = FALSE;
	ULONG64 eval_ret = 0;
	const char* string = luaL_checkstring(L, 1);
	DEBUG_VALUE debug_value = { 0 };
	ULONG old_type;
	ULONG return_index;
	g_Ext->m_Control3->GetExpressionSyntax(&old_type);
	g_Ext->m_Control3->SetExpressionSyntax(DEBUG_EXPR_CPLUSPLUS);

	HRESULT hr = g_Ext->m_Control3->Evaluate(string, DEBUG_VALUE_INT64, &debug_value, &return_index);
	if (SUCCEEDED(hr)) {
		if (debug_value.Type == DEBUG_VALUE_INT8) {
			eval_ret = debug_value.I8;
			ret = TRUE;
		}
		else if (debug_value.Type == DEBUG_VALUE_INT16) {
			eval_ret = debug_value.I16;
			ret = TRUE;
		}
		else if (debug_value.Type == DEBUG_VALUE_INT32) {
			eval_ret = debug_value.I32;
			ret = TRUE;
		}
		else if (debug_value.Type == DEBUG_VALUE_INT64) {
			eval_ret = debug_value.I64;
			ret = TRUE;
		}
		else {
			g_Ext->Err("Lua dose not support this value.\n");
		}
	}
	else {
		g_Ext->Err("Cannot evaluate value.\n");
	}

	g_Ext->m_Control3->SetExpressionSyntax(old_type);
	if (ret) {
		lua_pushinteger(L, eval_ret);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

static UCHAR CharToDigital(CHAR c)
{
	UCHAR ret = 0;
	if (c >= '0' && c <= '9') {
		ret = c - '0';
	}
	else if (c >= 'a' && c <= 'f') {
		ret = c - 'a' + 10;
	}
	else if (c >= 'A' && c <= 'F') {
		ret = c - 'A' + 10;
	}

	return ret;
}

static int StringToBytes(LPCSTR hex_str, CAutoVectorPtr<UCHAR> &hex_buffer)
{
	CStringA pure_hex_str;
	int hex_str_length = (int)strlen(hex_str);
	CHAR current_char;
	int i;
	for (i = 0; i < hex_str_length; i++) {
		current_char = hex_str[i];
		if ((current_char >= '0' && current_char <= '9') ||
			(current_char >= 'a' && current_char <= 'f') ||
			(current_char >= 'A' && current_char <= 'F')) {
			pure_hex_str += current_char;
		}
		else if (current_char == ' ' ||
			current_char == '\t' ||
			current_char == '\r' ||
			current_char == '\n') {
			continue;
		}
		else {
			return 0;
		}
	}

	if (pure_hex_str.GetLength() % 2 != 0) {
		return 0;
	}

	int buffer_length = pure_hex_str.GetLength() / 2;
	if (!hex_buffer.Allocate(buffer_length)) {
		return 0;
	}

	for (i = 0; i < pure_hex_str.GetLength(); i += 2) {
		hex_buffer[i / 2] = CharToDigital(pure_hex_str[i]);
		hex_buffer[i / 2] <<= 4;
		hex_buffer[i / 2] |= CharToDigital(pure_hex_str[i + 1]);
	}

	return buffer_length;
}

static int search(lua_State* L)
{
	BOOL ret = FALSE;
	ULONG64 match_offset = 0;
	ULONG64 search_offset = luaL_checkinteger(L, 1);
	ULONG64 search_length = luaL_checkinteger(L, 2);
	const char* string = luaL_checkstring(L, 3);

	CAutoVectorPtr<UCHAR> hex_buffer;
	int hex_buffer_length = StringToBytes(string, hex_buffer);
	if (hex_buffer_length != 0) {
		HRESULT hr = g_Ext->m_Data->SearchVirtual((ULONG64)search_offset,
			(ULONG64)search_length, hex_buffer.m_p, hex_buffer_length, 1, &match_offset);
		if (hr == S_OK) {
			ret = TRUE;
		}
	}
	else {
		g_Ext->Err("Search bytes error.\n");
	}

	if (ret) {
		lua_pushinteger(L, (lua_Integer)match_offset);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

static int get_symbolnamebyoffset(lua_State* L)
{
	ULONG64 offset = luaL_checkinteger(L, 1);
	char name[1024] = {0};
	ULONG name_length = sizeof(name);
	ULONG64 disp = 0;
	if (FAILED(g_Ext->m_Symbols->GetNameByOffset(offset, name, sizeof(name), &name_length, &disp))) {
		lua_pushnil(L);
		return 1;
	}

	CStringA sym_str;
	sym_str.Format("%s+0x%I64x", name, disp);
	lua_pushstring(L, sym_str.GetString());
	lua_pushstring(L, name);
	lua_pushinteger(L, disp);
	return 3;
}

static int get_symboloffsetbyname(lua_State* L)
{
	const char *name = luaL_checkstring(L, 1);
	ULONG64 offset = 0;
	if (FAILED(g_Ext->m_Symbols->GetOffsetByName(name, &offset))) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushinteger(L, offset);
	return 1;
}

static int input(lua_State* L)
{
	CHAR buffer[0x1000] = {0};
	ULONG input_length = 0;
	if (FAILED(g_Ext->m_Control4->Input(buffer, 0x1000, &input_length))) {
		lua_pushnil(L);
		return 1;
	}

	CStringA backspace;
	for (ULONG i = 0; i < input_length << 1; i++) {
		backspace.Append("\b");
	}
	g_Ext->Out(backspace.GetString());

	lua_pushstring(L, buffer);
	return 1;
}

static const struct luaL_Reg dbgbasic_func[] =
{
	{ "exec", exec },
	{ "exec_tostring", exec_tostring },
	{ "readbyte", readbyte },
	{ "readword", readword },
	{ "readdword", readdword },
	{ "readqword", readqword },
	{ "writebyte", writebyte },
	{ "writeword", writeword },
	{ "writedword", writedword },
	{ "writeqword", writeqword },
	{ "readwidestrng", readwidestrng },
	{ "readstring", readstring },
	{ "wait", wait },
	{ "evalmasm", evalmasm },
	{ "evalcpp", evalcpp },
	{ "search", search },
	{ "get_symbolnamebyoffset", get_symbolnamebyoffset },
	{ "get_symboloffsetbyname", get_symboloffsetbyname },
	{ "input", input },
	{ NULL, NULL }
};


static lua_State *CreateLuaState(void)
{
	lua_State *L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}

	luaL_openlibs(L);
	SetDefaultPrint(L);
	luaopen_dbgmodule(L);
	lua_pop(L, 1);
	luaopen_dbgtype(L);
	lua_pop(L, 1);
	luaopen_dbgreg(L);
	lua_pop(L, 1);
	luaopen_dbgmem(L);
	lua_pop(L, 1);
	luaopen_dbgthread(L);
	lua_pop(L, 1);

	lua_pushglobaltable(L);
	luaL_setfuncs(L, dbgbasic_func, 0);
	lua_pop(L, 1);
	return L;
}
EXT_COMMAND(lua,
	"Execute lua file.",
	"{;x,r;path;Execute lua file path.}")
{
	LPCSTR path = GetUnnamedArgStr(0);
	lua_State* L = CreateLuaState();
	if (L == NULL) {
		Err("Failed to create Lua state.\r\n");
		return;
	}

	if (luaL_dofile(L, path) != 0) {
		Err("lua error: %s\r\n", lua_tostring(L, -1));
	}

	lua_close(L);
}

EXT_COMMAND(luacmd,
	"Input lua command.",
	"")
{
	lua_State* L = CreateLuaState();
	if (L == NULL) {
		Err("Failed to create Lua state.\r\n");
		return;
	}

	CHAR buffer[0x1000] = {0};
	ULONG input_length = 0;
	while (SUCCEEDED(m_Control4->Input(buffer, 0x1000, &input_length))) {
		CStringA backspace;
		for (ULONG i = 0; i < input_length; i++) {
			backspace.Append("\b");
		}
		Out(backspace.GetString());

		if (strcmp(buffer, "quit()") == 0) {
			buffer[0] = 0;
			input_length = 0;
			break;
		}
		if (luaL_dostring(L, buffer) != 0) {
			Err("lua error: %s\r\n", lua_tostring(L, -1));
		}
		buffer[0] = 0;
		input_length = 0;
	}

	lua_close(L);
}

std::map<CStringA, lua_State*> g_lua_loaded_list;
std::set<CStringA> g_black_list;
std::mutex g_lua_state_mutex;

void EXT_CLASS::Uninitialize(void)
{
	std::lock_guard<std::mutex> lock(g_lua_state_mutex);
	for (std::map<CStringA, lua_State*>::iterator it = g_lua_loaded_list.begin();
		it != g_lua_loaded_list.end(); ++it) {
		lua_close(it->second);
	}
	g_lua_loaded_list.clear();
	g_black_list.clear();
	__super::Uninitialize();
}

void BlacklistSnapshot(lua_State *L) {

	lua_pushglobaltable(L);
	lua_pushnil(L);
	while (lua_next(L,-2) != 0) {
		lua_pushvalue(L, -2);
		const char *key = lua_tostring(L, -1);
		if (key != NULL) {
			g_black_list.insert(key);
		}
		lua_pop(L,2);
	}
	lua_pop(L,1);
}

EXT_COMMAND(luaload,
	"Load lua file.",
	"{;x,r;path;lua file path.}")
{
	LPCSTR lua_file = GetUnnamedArgStr(0);
	LPCSTR lua_name = PathFindFileNameA(lua_file);
	if (lua_name == NULL) {
		Err("Cannot find lua file name.\r\n");
		return;
	}

	CStringA lua_lwr = lua_name;
	LPSTR name_buffer = lua_lwr.GetBuffer(lua_lwr.GetLength());
	PathRemoveExtensionA(name_buffer);
	lua_lwr.ReleaseBuffer();
	lua_lwr.MakeLower();

	{
		std::lock_guard<std::mutex> lock(g_lua_state_mutex);
		if (g_lua_loaded_list.find(lua_lwr) != g_lua_loaded_list.end()) {
			Err("script '%s' is loaded.\r\n", lua_name);
			return;
		}
	}

	lua_State* L = CreateLuaState();
	if (L == NULL) {
		Err("Failed to create Lua state.\r\n");
		return;
	}

	{
		std::lock_guard<std::mutex> lock(g_lua_state_mutex);
		if (g_black_list.empty()) {
			BlacklistSnapshot(L);
		}
	}

	if (luaL_dofile(L, lua_file) != 0) {
		Err("lua error: %s\r\n", lua_tostring(L, -1));
		lua_close(L);
		return;
	}

	{
		std::lock_guard<std::mutex> lock(g_lua_state_mutex);
		g_lua_loaded_list[lua_lwr] = L;
	}
}

EXT_COMMAND(luaunload,
	"Unload lua file name.",
	"{;x,r;name;lua file name.}")
{
	LPCSTR lua_name = GetUnnamedArgStr(0);
	CStringA lua_lwr = lua_name;
	lua_lwr.MakeLower();

	{
		std::lock_guard<std::mutex> lock(g_lua_state_mutex);
		std::map<CStringA, lua_State*>::iterator ret = g_lua_loaded_list.find(lua_lwr);
		if (ret == g_lua_loaded_list.end()) {
			Err("Cannot unload '%s'.\r\n", lua_name);
			return;
		}

		lua_close(ret->second);
		g_lua_loaded_list.erase(ret);
	}
}

EXT_COMMAND(luado,
	"Execute lua code.",
	"{;x,r;lua string;lua code.}")
{
	LPCSTR lua_code = GetUnnamedArgStr(0);

	CStringA lua_code_str = lua_code;
	int pos = lua_code_str.Find("!");
	if (pos == -1) {
		Err("Cannot find script in code.\r\n");
		return;
	}

	CStringA script_name(lua_code_str, pos);
	script_name.MakeLower();

	CStringA code_str(lua_code_str.GetString() + pos + 1);

	lua_State* L = NULL;
	{
		std::lock_guard<std::mutex> lock(g_lua_state_mutex);
		std::map<CStringA, lua_State*>::iterator ret = g_lua_loaded_list.find(script_name);
		if (ret == g_lua_loaded_list.end()) {
			Err("Cannot find script in loaded list.\r\n");
			return;
		}
		L = ret->second;
	}
	if (luaL_dostring(L, code_str.GetString()) != 0) {
		Err("lua error: %s\r\n", lua_tostring(L, -1));
	}
}

void PrintIndent(int indent)
{
	for (int i = 0; i < indent; i++) {
		g_Ext->Out("  ");
	}
}

void PrintTable(lua_State *L, int indent)
{
	lua_pushnil(L);

	while(lua_next(L, -2) != 0) {

		lua_pushvalue(L, -2);
		lua_pushvalue(L, -2);

		const char *key = lua_tostring(L, -2);
		if (key == NULL || g_black_list.find(key) != g_black_list.end()) {
			lua_pop(L, 3);
			continue;
		}

		PrintIndent(indent);
		g_Ext->Out("[%s] %s ", lua_typename(L, lua_type(L, -1)), key);

		if(lua_isstring(L, -1)) {

			g_Ext->Out("= %s\r\n", lua_tostring(L, -1));
		}
		else if(lua_isnumber(L, -1)) {
			g_Ext->Out("= %s\r\n", lua_tostring(L, -1));
		}
		else if(lua_istable(L, -1)) {
			g_Ext->Out("\r\n");
			PrintTable(L, indent + 1);
		}
		else {
			g_Ext->Out("\r\n");
		}

		lua_pop(L, 3);
	}
}

EXT_COMMAND(lualist,
	"list loaded scripts.",
	"")
{
	std::lock_guard<std::mutex> lock(g_lua_state_mutex);
	for (std::map<CStringA, lua_State*>::iterator it = g_lua_loaded_list.begin();
		it != g_lua_loaded_list.end(); ++it) {
			Out("script: %s\r\n", it->first.GetString());

			lua_State* L = it->second;

			lua_pushglobaltable(L);
			PrintTable(L, 1);
			lua_pop(L,1);
	}

	Out("\r\n");
}
