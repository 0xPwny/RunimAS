import winim
import os, strutils, parseopt

proc CreateEnvironmentBlock(env: ptr pointer, token: HANDLE, inherit: WINBOOL): WINBOOL
  {.stdcall, dynlib: "userenv.dll", importc.}

proc DestroyEnvironmentBlock(env: pointer): WINBOOL
  {.stdcall, dynlib: "userenv.dll", importc.}

const
  LOGON32_PROVIDER_DEFAULT = 0
  LOGON32_LOGON_INTERACTIVE = 2
  LOGON32_LOGON_NETWORK = 3
  LOGON32_LOGON_BATCH = 4
  LOGON32_LOGON_SERVICE = 5
  LOGON32_LOGON_NETWORK_CLEARTEXT = 8
  LOGON32_LOGON_NEW_CREDENTIALS = 9
  CREATE_NO_WINDOW = 0x08000000
  CREATE_UNICODE_ENVIRONMENT = 0x00000400

type
  RunasCsError = object of CatchableError

  ProcessConfig = object
    username: string
    password: string
    domain: string
    command: string
    logonType: DWORD
    timeout: DWORD
    redirect: tuple[host: string, port: int]  # Reserved for future use

proc raiseError(msg: string) =
  let errCode = GetLastError()
  var errMsg: array[0..255, WCHAR]
  let len = FormatMessageW(
    FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_IGNORE_INSERTS,
    nil,
    errCode,
    0,
    cast[LPWSTR](addr errMsg),
    DWORD(errMsg.len),
    nil
  )

  if len == 0:
    raise newException(RunasCsError, msg & " (Failed to get error message)")

  let errorString = $cast[WideCString](addr errMsg)
  raise newException(RunasCsError, msg & " Error: " & errorString.strip)

proc createProcessWithLogon(
  username, domain, password, command: string
): PROCESS_INFORMATION =
  var si: STARTUPINFOW
  var pi: PROCESS_INFORMATION
  ZeroMemory(addr si, sizeof(si))
  ZeroMemory(addr pi, sizeof(pi))
  si.cb = sizeof(si).DWORD

  let wCommand = newWideCString(command)
  let wUsername = newWideCString(username)
  let wDomain = newWideCString(domain)
  let wPassword = newWideCString(password)

  let res = CreateProcessWithLogonW(
    wUsername,
    wDomain,
    wPassword,
    LOGON_WITH_PROFILE,
    nil,
    wCommand,
    0,  	      #CREATE_NO_WINDOW,
    nil,
    nil,
    addr si,
    addr pi
  )

  if res == 0:
    raiseError("CreateProcessWithLogonW failed")

  return pi

proc createProcessAsUser(
  token: HANDLE, command: string, env: pointer
): PROCESS_INFORMATION =
  var si: STARTUPINFOW
  var pi: PROCESS_INFORMATION
  ZeroMemory(addr si, sizeof(si))
  ZeroMemory(addr pi, sizeof(pi))
  si.cb = sizeof(si).DWORD

  let wCommand = newWideCString(command)

  let res = CreateProcessAsUserW(
    token,
    nil,
    wCommand,
    nil,
    nil,
    FALSE,
    CREATE_NO_WINDOW or CREATE_UNICODE_ENVIRONMENT,
    env,
    nil,
    addr si,
    addr pi
  )

  if res == 0:
    raiseError("CreateProcessAsUserW failed")

  return pi

proc logonUser(
  username, domain, password: string, logonType: DWORD
): HANDLE =
  var token: HANDLE
  let wUsername = newWideCString(username)
  let wDomain = newWideCString(domain)
  let wPassword = newWideCString(password)

  let res = LogonUserW(
    wUsername,
    wDomain,
    wPassword,
    logonType,
    LOGON32_PROVIDER_DEFAULT,
    addr token
  )

  if res == 0:
    raiseError("LogonUserW failed")

  return token

proc createEnvironmentBlock(token: HANDLE): pointer =
  var env: pointer
  if CreateEnvironmentBlock(addr env, token, FALSE) == 0:
    raiseError("CreateEnvironmentBlock failed")
  return env

proc runAs(config: ProcessConfig): string =
  var 
    token: HANDLE = 0
    env: pointer = nil
    pi: PROCESS_INFORMATION
  ZeroMemory(addr pi, sizeof(pi))

  try:
    token = logonUser(config.username, config.domain, config.password, config.logonType)

    if config.logonType == LOGON32_LOGON_NEW_CREDENTIALS:
      env = createEnvironmentBlock(token)
      pi = createProcessAsUser(token, config.command, env)
    else:
      pi = createProcessWithLogon(config.username, config.domain, config.password, config.command)

    if config.timeout > 0:
      discard WaitForSingleObject(pi.hProcess, config.timeout)
      var exitCode: DWORD
      discard GetExitCodeProcess(pi.hProcess, addr exitCode)
      return "Process exited with code: " & $exitCode

    return "Process started with PID: " & $pi.dwProcessId

  finally:
    if token != 0: CloseHandle(token)
    if env != nil: discard DestroyEnvironmentBlock(env)
    if pi.hProcess != 0: CloseHandle(pi.hProcess)
    if pi.hThread != 0: CloseHandle(pi.hThread)

proc parseCmdLine(): ProcessConfig =
  var config: ProcessConfig
  var p = initOptParser()
  var argsCount = 0

  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key.toLower()
      of "d", "domain": config.domain = p.val
      of "l", "logon-type": config.logonType = parseUInt(p.val).DWORD
      of "t", "timeout": config.timeout = parseUInt(p.val).DWORD
      else: discard
    of cmdArgument:
      case argsCount
      of 0: config.username = p.key
      of 1: config.password = p.key
      of 2: config.command = p.key
      else: config.command.add(" " & p.key)
      inc argsCount

  if config.username.len == 0 or config.password.len == 0 or config.command.len == 0:
    raise newException(RunasCsError, "Missing required arguments: username, password, and command")

  return config

when isMainModule:
  try:
    let config = parseCmdLine()
    echo runAs(config)
  except RunasCsError as e:
    stderr.writeLine "Error: ", e.msg
    quit(1)
