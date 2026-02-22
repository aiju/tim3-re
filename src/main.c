#include <windows.h>
#include <string.h>

extern HINSTANCE g_instance;
extern HWND g_mainWindow;
extern int g_exitCode;

void gameMain(void);

extern char **g_argv;
void *gameAlloc(int size, int flags);

int buildArgv(char *cmd_line)
{
	char c;
	char *p;
	int i;
	int *argv;
	int *dst;
	int argc;

	if (g_argv != NULL) {
		free(g_argv);
		g_argv = NULL;
	}
	argc = 0;
	p = cmd_line;
	while (p != NULL && *p != '\0') {
		for (; (c = *p) != '\0' && c == ' '; p++)
			;
		if (*p != '\0')
			argc++;
		while ((c = *p) != '\0' && c != ' ') {
			if (c == '"') {
				for (; (c = *p) != '\0' && c != '"'; p++)
					;
			} else {
				p++;
			}
		}
	}
	if (argc == 0) {
		argc = 0;
	} else {
		argv = (int *)gameAlloc(strlen(cmd_line) + (argc + 1) * 4 + 1, 1);
		if (argv == NULL) {
			argc = 0;
		} else {
			dst = argv + argc + 1;
			i = 0;
			g_argv = (char **)argv;
			if (0 < argc) {
				do {
					g_argv[i] = (char *)dst;
					for (; (c = *cmd_line) != '\0' && c == ' '; cmd_line++)
						;
					while ((c = *cmd_line) != '\0' && c != ' ') {
						if (c == '"') {
							cmd_line++;
							while ((c = *cmd_line) != '\0' && c != '"') {
								*(char *)dst = c;
								dst = (int *)((int)dst + 1);
								cmd_line++;
							}
							if (*cmd_line != '\0')
								cmd_line++;
						} else {
							*(char *)dst = *cmd_line;
							cmd_line++;
							dst = (int *)((int)dst + 1);
						}
					}
					*(char *)dst = '\0';
					dst = (int *)((int)dst + 1);
					i++;
				} while (i < argc);
			}
		}
	}
	return argc;
}

BOOL chdirToExePath(char *path)
{
	BOOL ok;
	char *dot_pos;
	char buf[260];

	ok = SetCurrentDirectoryA(path);
	if (ok == 0) {
		dot_pos = strrchr(path, '.');
		if (strrchr(path, '\\') < dot_pos) {
			strcpy(buf, path);
			strcat(buf, "\\..");
			ok = SetCurrentDirectoryA(buf);
		}
	}
	return ok;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	int exit_code;
	char buf[280];

	if (hPrevInstance != 0)
		return 0;
	g_instance = hInstance;
	GetModuleFileNameA(g_instance, buf, 0x118);
	strcpy(strrchr(buf, '\\'), NULL);
	chdirToExePath(buf);
	buildArgv(lpCmdLine);
	gameMain();
	if (g_mainWindow != NULL)
		DestroyWindow(g_mainWindow);
	exit_code = g_exitCode;
	return exit_code;
}
