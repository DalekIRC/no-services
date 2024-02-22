/*
  Licence: GPLv3
  Copyright Ⓒ 2024 Valerie Pond
  */
#define NOSERVICES_VERSION "1.3.1.3"

/*** <<<MODULE MANAGER START>>>
module
{
		documentation "https://github.com/DalekIRC/no-services/wiki";
		troubleshooting "In case of problems, documentation or e-mail me at v.a.pond@outlook.com";
		min-unrealircd-version "6.1.3";
		max-unrealircd-version "6.*";
		post-install-text {
				"The module is installed. Now all you need to do is add a loadmodule line:";
				"loadmodule \"third/no-services\";";
				"And /REHASH the IRCd.";
				"The module does not need any other configuration.";
		}
}
*** <<<MODULE MANAGER END>>>
*/

#include "unrealircd.h"

/* Defines */
#define END_OF_HELP NULL

#define NO_SERVICES_CONF "no-services"
#define REGCAP_NAME "draft/account-registration"

#define CERTFP_DEL 0
#define CERTFP_ADD 1
#define CERTFP_LIST 2

#define SR_FAIL 0
#define SR_WARN 1
#define SR_NOTE 2

#define MAX_BUDDYLIST_SIZE 100
// Runs both when a fully-connected user authenticates or an authenticated user fully-connects lol
#define HOOKTYPE_NOSERV_CONNECT_AND_LOGIN 159

/** Called when a local user quits or otherwise disconnects (function prototype for HOOKTYPE_PRE_LOCAL_QUIT).
 * @param client		The client
 * @param result		 	A JSON object about the user
 *
 *	{
 *		"id": 29,
 *		"account_name": "bob",
 *		"first_name": null,
 *		"last_name": null,
 *		"password": "$argon2id$v=19$m=6144,t=2,p=2$P5bUJuJSarijl8abOiV1Lw$GIbxA06zp3Kk1pjWjcSc8E0MwgfBUAuO5MjfhYpksUI",
 *		"email": "bob@example.cn",
 *		"activated": null,
 *		"last_login": null,
 *		"registered_at": "2023-12-10 23:38:06",
 *		"roles": null,
 *		"meta": {
 *		"0": {
 *			"id": 11,
 *			"user_id": "bob",
 *			"meta_name": "ajoin",
 *			"meta_value": "#services"
 *		},
 *		"1": {
 *			"id": 12,
 *			"user_id": "bob",
 *			"meta_name": "ajoin",
 *			"meta_value": "#opers"
 *		}
 *	}
 *
 *	For an actual example, see `void do_ajoin(){...}`
 */

void hooktype_noserv_connect_and_login(Client *client, json_t *result);
// sasl stuff
#define SASL_TYPE_NONE 0
#define SASL_TYPE_PLAIN 1
#define SASL_TYPE_EXTERNAL 2

#define MTAG_ISO_LANG "+valware.uk/iso-lang"
#define MTAG_RESPONDER "valware.uk/responder"

#define SetLanguage(x, y)	do { moddata_client_set(x, "language", y); } while (0)
#define GetLanguage(x)	moddata_client_get(x, "language")

#define GetSaslType(x)			(moddata_client(x, sasl_md).i)
#define SetSaslType(x, y)		do { moddata_client(x, sasl_md).i = y; } while (0)
#define DelSaslType(x)		do { moddata_client(x, sasl_md).i = SASL_TYPE_NONE; } while (0)
ModDataInfo *sasl_md;

// nick enforcement
#define UserRequiresLogin(x)			(moddata_client(x, need_login).i)
#define RequireLogin(x)		do { moddata_client(x, need_login).i = 1; } while (0)
#define UnrequireLogin(x)		do { moddata_client(x, need_login).i = 0; } while (0)
ModDataInfo *need_login;
// password for login/sasl
#define GetPassword(x)			moddata_client_get(x, "login_cred")
#define SetPassword(x, y)		do { moddata_client(x, login_cred).str = strdup(y); } while (0)
#define UnsetPassword(x)		do { moddata_client_set(x, "login_cred", NULL); } while (0)
ModDataInfo *login_cred;

// nick drop key
#define WantsToDrop(x)		do { moddata_client_set(x, need_drop, "1"); } while (0)
#define NoLongerWantsToDrop(x)	do { moddata_client(x, need_drop, "0"); } while (0)
ModDataInfo *need_drop;

// nick drop key
#define GetDropKey(x)			(moddata_client(x, drop_key_md).i)
#define SetDropKey(x, y)		do { moddata_client(x, drop_key_md).i = y; } while(0)
#define UnsetDropKey(x)			do { moddata_client(x, drop_key_md).i = 0; } while(0)
ModDataInfo *drop_key_md;

void setcfg(void);
void freecfg(void);
int noservices_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
int noservices_configrun(ConfigFile *cf, ConfigEntry *ce, int type);

void connect_query_user(Client *client);
void account_enforce_check(Client *client);

long CAP_ACCOUNTREGISTRATION = 0L;
long CAP_SASL_OVR = 0L;

char *construct_url(const char *base_url, const char *extra_params);
const char *accreg_capability_parameter(Client *client);
int accreg_capability_visible(Client *client);
void register_account(OutgoingWebRequest *request, OutgoingWebResponse *response);
void register_channel_callback(OutgoingWebRequest *request, OutgoingWebResponse *response);
void ns_account_login(OutgoingWebRequest *request, OutgoingWebResponse *response);
void ajoin_callback(OutgoingWebRequest *request, OutgoingWebResponse *response);
void connect_query_user_response(OutgoingWebRequest *request, OutgoingWebResponse *response);
void certfp_callback(OutgoingWebRequest *request, OutgoingWebResponse *response);
void nick_account_enforce(OutgoingWebRequest *request, OutgoingWebResponse *response);
void setpassword_callback(OutgoingWebRequest *request, OutgoingWebResponse *response);
void drop_callback(OutgoingWebRequest *request, OutgoingWebResponse *response);
void ns_account_identify(OutgoingWebRequest *request, OutgoingWebResponse *response);
void translate_callback(OutgoingWebRequest *request, OutgoingWebResponse *response);

// draft/account-registration= parameter MD
void regkeylist_free(ModData *m);
const char *regkeylist_serialize(ModData *m);
void regkeylist_unserialize(const char *str, ModData *m);

// If someone wants to drop their nick
void wtdrop_free(ModData *m);
const char *wtdrop_serialize(ModData *m);
void wtdrop_unserialize(const char *str, ModData *m);

// A key if someone wants to drop their account
void dropkey_free(ModData *m);
const char *dropkey_serialize(ModData *m);
void dropkey_unserialize(const char *str, ModData *m);

// Who's SASLing how
void sat_free(ModData *m);
const char *sat_serialize(ModData *m);
void sat_unserialize(const char *str, ModData *m);

// Who's SASLing how
void need_login_free(ModData *m);
const char *need_login_serialize(ModData *m);
void need_login_unserialize(const char *str, ModData *m);
void login_cred_free(ModData *m);
const char *login_cred_serialize(ModData *m);
void login_cred_unserialize(const char *str, ModData *m);

int noservices_hook_local_connect(Client *client);
int noservices_hook_post_local_nickchange(Client *client, MessageTag *mtags, const char *oldnick);
int auto_translate(Client *from, Client *to, MessageTag *mtags, const char *text, SendType sendtype);

void do_ajoin(Client *client, json_t *result);
void do_account_drop(const char *account, const char *callback_uid);

int sasl_capability_visible(Client *client);
const char *sasl_capability_parameter(Client *client);

CMD_OVERRIDE_FUNC(cmd_authenticate_ovr);
CMD_OVERRIDE_FUNC(cmd_nick_ovr);
CMD_OVERRIDE_FUNC(cmd_privmsg_ovr);
CMD_FUNC(cmd_register);
CMD_FUNC(cmd_cregister);
CMD_FUNC(cmd_ajoin);
CMD_FUNC(cmd_identify);
CMD_FUNC(cmd_logout);
CMD_FUNC(cmd_salogout);
CMD_FUNC(cmd_certfp);
CMD_FUNC(cmd_release);
CMD_FUNC(cmd_drop);
CMD_FUNC(cmd_setpassword);
CMD_FUNC(cmd_sadrop);
CMD_FUNC(cmd_tban);
CMD_FUNC(cmd_bot);
CMD_FUNC(cmd_access);

EVENT(nick_enforce);

int responder_is_ok(Client *client, const char *name, const char *value);



// case insensitive version of strstr()
char *strcasestr(const char* haystack, const char* needle) {
    if (*needle == '\0') {
        return (char*) haystack; // Empty needle, return the haystack
    }

    while (*haystack != '\0') {
        // Find the first character of the needle in the haystack
        while (toupper(*haystack) != toupper(*needle)) {
            if (*haystack == '\0') {
                return NULL; // Reached the end of the haystack without finding the needle
            }
            haystack++;
        }

        // Compare the rest of the needle and the corresponding part of the haystack
        const char* h = haystack;
        const char* n = needle;
        while (toupper(*h) == toupper(*n)) {
            if (*n == '\0') {
                return (char*) haystack; // Found the needle in the haystack
            }
            h++;
            n++;
        }
        
        // Continue searching in the haystack
        haystack++;
    }

    return NULL; // Needle not found
}
char *json_user_object_get_property(json_t *user_obj, const char *property_name)
{
	const char *key;
	char *ret = NULL;

	json_t *value;
	json_object_foreach(user_obj, key, value)
	{
		if (!strcasecmp(key, property_name))
			ret = strdup(json_string_value(value));
	}
	return ret;
}

char *json_user_object_get_meta(json_t *user_obj, const char *meta_name)
{
	const char *key, *key2;
	char *ret = NULL;
	json_t *value, *value2;

	json_object_foreach(user_obj, key, value)
	{
		if (strcasecmp(key, "meta") != 0)
			continue;
		json_object_foreach(value, key2, value2)
		{
			if (!strcasecmp(key, meta_name))
				ret = strdup(json_string_value(value2));
		}
	}
	return ret;
}

int random_number(int low, int high)
{
	int number = rand() % ((high+1) - low) + low;
	return number;
}

char *uppercaseString(const char* input)
{
	size_t length = strlen(input);
	
	// Allocate memory for the new string
	char* result = (char*)malloc(length + 1);
	if (result == NULL)
	{
		// Handle memory allocation error
		exit(EXIT_FAILURE);
	}

	// Copy the input string and convert each character to uppercase
	for (size_t i = 0; i < length; ++i)
	{
		result[i] = toupper(input[i]);
	}

	// Null-terminate the new string
	result[length] = '\0';

	return result;
}

/* These are two local (static) buffers used by the various send functions */
static char sendbuf[MAXLINELENGTH];
static char sendbuf2[MAXLINELENGTH];

/** Send a message to a single client - va_list variant.
 * This function is similar to sendto_one() except that it
 * doesn't use varargs but uses a va_list instead.
 * Generally this function is NOT used outside send.c, so not by modules.
 * @param to		The client to send to
 * @param mtags		Any message tags associated with this message (can be NULL)
 * @param pattern	The format string / pattern to use.
 * @param vl		Format string parameters.
 */
void vsendto_one(Client *to, MessageTag *mtags, const char *pattern, va_list vl)
{
	const char *mtags_str = mtags ? mtags_to_string(mtags, to) : NULL;

	/* Need to ignore -Wformat-nonliteral here */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
	ircvsnprintf(sendbuf, sizeof(sendbuf)-3, pattern, vl);
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

	if (BadPtr(mtags_str))
	{
		/* Simple message without message tags */
		sendbufto_one(to, sendbuf, 0);
	} else {
		/* Message tags need to be prepended */
		snprintf(sendbuf2, sizeof(sendbuf2)-3, "@%s %s", mtags_str, sendbuf);
		sendbufto_one(to, sendbuf2, 0);
	}
}

/*** TRANSLATION THINGS */

#define IsAutoTranslate(x)	(x->umodes & UMODE_TRANSLATE)
/* Global variables */
long UMODE_TRANSLATE = 0L;

// Define a structure to hold ISO language information
typedef struct {
	char code[8];
	char name[70];
} ISO_Language;

const ISO_Language iso_language_list[] = {
	{ "AR", "Arabic" },
	{ "BG", "Bulgarian" },
	{ "CS", "Czech" },
	{ "DA", "Danish" },
	{ "DE", "German" },
	{ "EL", "Greek" },
	{ "EN-GB", "English (British)" },
	{ "EN-US", "English (American)" },
	{ "ES", "Spanish" },
	{ "ET", "Estonian" },
	{ "FI", "Finnish" },
	{ "FR", "French" },
	{ "HU", "Hungarian" },
	{ "ID", "Indonesian" },
	{ "IT", "Italian" },
	{ "JA", "Japanese" },
	{ "KO", "Korean" },
	{ "LT", "Lithuanian" },
	{ "LV", "Latvian" },
	{ "NB", "Norwegian (Bokmål)" },
	{ "NL", "Dutch" },
	{ "PL", "Polish" },
	{ "PT-BR", "Portuguese (Brazilian)" },
	{ "PT-PT", "Portuguese (all Portuguese varieties excluding Brazilian Portuguese)" },
	{ "RO", "Romanian" },
	{ "RU", "Russian" },
	{ "SK", "Slovak" },
	{ "SL", "Slovenian" },
	{ "SV", "Swedish" },
	{ "TR", "Turkish" },
	{ "UK", "Ukrainian" },
	{ "ZH", "Chinese (simplified)" }
};

// Function to check if a given string is a valid ISO language code
bool isValidISOLanguageCode(const char *code) {
	int i;
	for (i = 0; i < sizeof(iso_language_list) / sizeof(iso_language_list[0]); i++) {
		if (strcasecmp(code, iso_language_list[i].code) == 0)
			return true;
	}
	return false;
}


int iso_lang_mtag_is_ok(Client *client, const char *name, const char *value)
{
	if (isValidISOLanguageCode(value))
		return 1;

	sendto_one(client, NULL, ":%s NOTE * INVALID_MTAG_VALUE %s :Value for tag \"%s\" must be a valid ISO language code, for example EN-GB (British English)", me.name, value, name);
	return 0;
}

void mtag_add_iso_lang(Client *client, MessageTag *recv_mtags, MessageTag **mtag_list, const char *signature)
{
	MessageTag *m;

	if (IsUser(client))
	{
		m = find_mtag(recv_mtags, MTAG_ISO_LANG);
		if (m)
		{
			m = duplicate_mtag(m);
			AddListItem(m, *mtag_list);
		}
	}
}

void language_free(ModData *m)
{
	safe_free(m->str);
}

const char *language_serialize(ModData *m)
{
	if (!m->str)
		return NULL;
	return m->str;
}

void language_unserialize(const char *str, ModData *m)
{
	safe_strdup(m->str, str);
}

CMD_FUNC(cmd_setlang);


/*** BOT THINGS AND STUFF */
typedef struct BotCommand BotCommand;

struct BotCommand {
	char command[50];
	char helptext[250];
	struct BotCommand *prev, *next;
};

// Function to create a new bot command node
BotCommand* create_bot_command(const char* command, const char* helptext)
{
	BotCommand* newCommand = (BotCommand*)malloc(sizeof(BotCommand));
	if (newCommand == NULL)
	{
		// Handle memory allocation failure
		exit(EXIT_FAILURE);
	}
	strcpy(newCommand->command, command);
	strcpy(newCommand->helptext, helptext);
	newCommand->prev = NULL;
	newCommand->next = NULL;
	return newCommand;
}

// Function to insert a new bot command at the beginning of the doubly-linked list
BotCommand* insert_bot_command(BotCommand* head, const char* command, const char* helptext)
{
	BotCommand* newCommand = create_bot_command(command, helptext);
	newCommand->next = head;
	if (head != NULL)
	{
		head->prev = newCommand;
	}
	return newCommand;
}

// Function to display all bot commands in the doubly-linked list
void displayBotCommands(BotCommand* head)
{
	BotCommand* current = head;
	while (current != NULL)
	{
		printf("Command: %s\n", current->command);
		printf("HelpText: %s\n", current->helptext);
		printf("\n");
		current = current->next;
	}
}


// Function to handle bot commands received from IRC
void handle_bot_command(const char* botName, const char* command)
{
	// You can implement logic here to process the bot command
	printf("Bot %s received command: %s\n", botName, command);
}

// Function to free the memory allocated for the doubly-linked list
void free_bot_commands(BotCommand* head)
{
	BotCommand* current = head;
	while (current != NULL)
	{
		BotCommand* next = current->next;
		free(current);
		current = next;
	}
}

// Function to delete a specific bot command from the doubly-linked list
BotCommand* delete_bot_command(BotCommand* head, const char* commandToDelete)
{
	BotCommand* current = head;

	// Search for the command to delete
	while (current != NULL)
	{
		if (strcmp(current->command, commandToDelete) == 0)
		{
			if (current->prev != NULL)
			{
				current->prev->next = current->next;
			} else {
				// Deleting the first node, update head
				head = current->next;
			}

			if (current->next != NULL)
			{
				current->next->prev = current->prev;
			}

			free(current);
			break;
		}

		current = current->next;
	}

	return head;  // Return the updated head of the list
}

typedef struct Bot Bot;

struct Bot {
	char name[NICKLEN + 1];
	BotCommand *cmdslist;
	MultiLine *helptext;
	struct Bot *prev, *next;
};

// Function to add a new command to a bot
void add_command_to_bot(Bot* bot, const char* command, const char* helpText)
{
	BotCommand* newCommand = (BotCommand*)malloc(sizeof(BotCommand));
	if (newCommand == NULL)
	{
		// Handle memory allocation error
		exit(EXIT_FAILURE);
	}

	strncpy(newCommand->command, uppercaseString(command), sizeof(newCommand->command));
	strncpy(newCommand->helptext, helpText, sizeof(newCommand->helptext));

	newCommand->next = bot->cmdslist;
	bot->cmdslist = newCommand;
}

// Function to remove a command from a bot
void remove_command_from_bot(Bot* bot, const char* command)
{
	BotCommand* current = bot->cmdslist;
	BotCommand* prev = NULL;

	while (current != NULL)
	{
		if (strcasecmp(current->command, command) == 0)
		{
			if (prev == NULL)
			{
				bot->cmdslist = current->next;
			} else {
				prev->next = current->next;
			}

			free(current);
			return;
		}

		prev = current;
		current = current->next;
	}
}

bool BotHasCommand(Bot *bot, const char *cmd)
{
	BotCommand* current = bot->cmdslist;
	while (current != NULL)
	{
		if (strcasecmp(current->command, cmd) == 0)
		{
			return true;
		}
		current = current->next;
	}
	return false;
}

/* Config struct*/
struct cfgstruct {
	char *url;
	char *key;

	unsigned short int got_url;
	unsigned short int got_key;
	unsigned short int got_password_strength_requirement;
	unsigned short int got_guest_nick;
	unsigned short int got_nick_enforcement_timeout;

	// account registration
	int register_before_connect;
	int register_custom_account;
	int register_email_required;
	int password_strength_requirement;
	
	long nick_enforce_timeout;
	char *guest_nick;

	Bot *bot_node; // head of linked list
};

static struct cfgstruct cfg;

void bot_sendnotice(Bot *from, Client *target, FORMAT_STRING(const char *pattern), ...)
{
	if (!from)
		return;
	va_list vl;
	
	char buffer[512];

	// Use snprintf to modify the string in the buffer
	snprintf(buffer, sizeof(buffer), ":%s!%s@%s NOTICE %s :%s", from->name, from->name, me.name, target->name, pattern);

	// Use the same buffer for the new const char*
	const char* newString = buffer;

	va_start(vl, pattern);
	vsendto_one(target, NULL, newString, vl);
	va_end(vl);
}

Bot *AddBot(const char *name)
{
	Bot *newBot = (Bot *)malloc(sizeof(Bot));
	if (newBot != NULL)
	{
		strncpy(newBot->name, name, NICKLEN);
		newBot->cmdslist = NULL;
		newBot->next = cfg.bot_node;
		newBot->prev = NULL;

		if (cfg.bot_node != NULL)
		{
			cfg.bot_node->prev = newBot;
		}

		cfg.bot_node = newBot;
	}
	return newBot;
}

void DelBot(const char *name)
{
	Bot *currentBot = cfg.bot_node;

	while (currentBot != NULL)
	{
		if (strcasecmp(currentBot->name, name) == 0) 
		{
			if (currentBot->prev != NULL)
			{
				currentBot->prev->next = currentBot->next;
			} else {
				cfg.bot_node = currentBot->next;
			}

			if (currentBot->next != NULL)
			{
				currentBot->next->prev = currentBot->prev;
			}

			free(currentBot);
			break;
		}

		currentBot = currentBot->next;
	}
}

Bot *find_bot(const char *name)
{
	Bot *currentBot = cfg.bot_node;

	while (currentBot != NULL)
	{
		if (strcasecmp(currentBot->name, name) == 0)
		{
			return currentBot;
		}
		currentBot = currentBot->next;
	}

	return NULL;  // Bot not found
}

void free_bot_node()
{
	Bot *currentBot = cfg.bot_node;
	Bot *nextBot;

	while (currentBot != NULL)
	{
		nextBot = currentBot->next;
		free_bot_commands(currentBot->cmdslist);
		free(currentBot);
		currentBot = nextBot;
	}

	cfg.bot_node = NULL;
}

/* adds the responder message-tag to the given &list */
void mtag_add_responder(MessageTag **mtags, Bot *bot)
{
	MessageTag *m;
	if (!bot)
		return;
	m = safe_alloc(sizeof(MessageTag));
	safe_strdup(m->name, MTAG_RESPONDER);
	safe_strdup(m->value, bot->name);
	AddListItem(m, *mtags);
}

void rehash_check_bline(void)
{
	Client *cptr;
	Bot *bot;
	list_for_each_entry(cptr, &client_list, client_node)
	{
		if ((bot = find_bot(cptr->name)))
		{
			const char *comment = "Overridden";
			int n;

			/* for new_message() we use target here, makes sense for the exit_client, right? */
			if (!MyConnect(cptr))
				sendto_server(NULL, 0, 0, NULL, ":%s SVSKILL %s :%s", me.name, cptr->id, comment);
			SetKilled(cptr);
			dead_socket(cptr, comment);
		}
	}
}
/** "Test" the "validity" of emails*/
int IsValidEmail(const char *str)
{
	if (!strstr(str, "@"))
		return 0;
	if (!strstr(str, "."))
		return 0;

	return 1;
}

// copied from source: src/rpc/name_bans.c
TKL *my_find_tkl_nameban(const char *name)
{
	TKL *tkl;

	for (tkl = tklines[tkl_hash('Q')]; tkl; tkl = tkl->next)
	{
		if (!TKLIsNameBan(tkl))
			continue;
		if (!strcasecmp(name, tkl->ptr.nameban->name))
			return tkl;
	}
	return NULL;
}

/** Checks the strength of a given password
 * @param password The password to check
 * @param int Value between 0 and 4, 0 = no validation, 4 = require a very strong password
*/
int check_password_strength_dalek(const char *password, int password_strength_requirement)
{
	int length = strlen(password);
	int uppercase = 0, lowercase = 0, digits = 0, symbols = 0;
	
	for (int i = 0; i < length; i++)
	{
		if (isupper(password[i]))
		{
			uppercase = 1;
		} else if (islower(password[i]))
		{
			lowercase = 1;
		} else if (isdigit(password[i]))
		{
			digits = 1;
		} else {
			symbols = 1;
		}
	}
	
	int strength = uppercase + lowercase + digits + symbols;

	if (length >= 8 && strength >= password_strength_requirement)
	{
		return 1; // Password meets strength requirement
	} else {
		return 0; // Password does not meet strength requirement
	}
}

/** special send()
 * This function lets you send one thing to a user in two different manners depending on whether
 * there is a bot required to reply to the user, the latter being a fallback for the former: 
 * 1) The first way is via a bot which is defined by config. This sends a notice to the user just like classic services.
 * 2) The second way is via IRCv3 Standard Replies.
 *
 * @param from The Bot struct to send the notice from. (Can be NULL for forced Standard Replies.)
 * @param to The client to send the message to.
 * @param success 0 = Fail, 1 = Warn, 2 = NOTE (Not shown in bot notices)
 * @param cmd The command the user tried to issue (Not shown in bot notices)
 * @param msg The associated error code/message (NOT_ON_CHANNEL, INVALID_EMAIL, etc)
 * @param extra Any extra data to show to the client, such as any parameters they might have passed
 * @param pattern The human-readible format string/pattern to use (e.g.: "That email address is invalid :%s")
 * @returns Returns nothing
*/
void special_send(Bot *from, Client *to, int success, const char *cmd, const char *msg, const char *extra, FORMAT_STRING(const char *pattern), ...)
{
	va_list vl;
	
	char buffer[512];
	char sreply[5];

	if (strstr(cmd, " ") || strstr(msg, " ")) // no spaces allowed
		return;

	if (!success)
		snprintf(sreply, sizeof(sreply), "%s", "FAIL");

	else if (success == 1)
		snprintf(sreply, sizeof(sreply), "%s", "WARN");

	else if (success == 2)
		snprintf(sreply, sizeof(sreply), "%s", "NOTE");

	// Use snprintf to modify the string in the buffer
	if (from)
		snprintf(buffer, sizeof(buffer), ":%s!%s@%s NOTICE %s :%s (%s: %s)", from->name, from->name, me.name, to->name, pattern, msg, (extra) ? extra : "*");
	else
		snprintf(buffer, sizeof(buffer), ":%s %s %s %s %s :%s", me.name, sreply, cmd, msg, ((extra)) ? extra : "*", pattern);

	// Use the same buffer for the new const char*
	const char* newString = buffer;

	va_start(vl, pattern);
	vsendto_one(to, NULL, newString, vl);
	va_end(vl);
}

/** Check a client's stored password against a hash
 * @param client The client whose password to check
 * @param hash The hash to check against
 * @returns Boolean
 */
bool is_correct_password(Client *client, const char *hash)
{
	if (!client)
	{
		return false;
	}
	const char *local_pass = GetPassword(client);
	if (!local_pass)
	{
		return false;
	}
	if (argon2_verify(hash, local_pass, strlen(local_pass), Argon2_id) == ARGON2_OK)
	{
		return true;
	}
	return false;
}


/** checks the validity of nicks
 * @param nick The nick to check
 * @returns Boolean
*/
bool is_valid_nick(const char *nick)
{
	// Check if the nickname is not NULL
	if (nick == NULL)
	{
		return false;
	}

	int length = strlen(nick);

	// Check if the length is within the valid range
	if (length < 1 || length > NICKLEN)
	{
		return false;
	}

	// Check if the first character is a letter
	if (!isalpha(nick[0]))
	{
		return false;
	}

	// Check if the remaining characters are letters, numbers, underscores, or hyphens
	for (int i = 1; i < length; ++i)
	{
		if (!isalnum(nick[i]) && nick[i] != '_' && nick[i] != '-')
		{
			return false;
		}
	}

	// If all checks pass, the nickname is valid
	return true;
}

/** Query the No-Services API
 @param endpoint The endpoint of the API
 @param body The body to POST, typically JSON
 @param callback The callback function
 @returns Void
*/
void query_api(const char *endpoint, char *body, const char *callback)
{
	OutgoingWebRequest *w = safe_alloc(sizeof(OutgoingWebRequest));
	json_t *j;
	NameValuePrioList *headers = NULL;
	add_nvplist(&headers, 0, "Content-Type", "application/json; charset=utf-8");
	add_nvplist(&headers, 0, "X-API-Key", cfg.key);
	/* Do the web request */
	char *our_url = construct_url(cfg.url, endpoint);
	safe_strdup(w->url, our_url);
	w->http_method = HTTP_METHOD_POST;
	w->body = body;
	w->headers = headers;
	w->max_redirects = 1;
	safe_strdup(w->apicallback, callback);
	url_start_async(w);
	free(our_url);
}

// basically strncat but with a new char in memorayyy
char *construct_url(const char *base_url, const char *extra_params)
{
	size_t base_len = strlen(base_url) +1;
	size_t params_len = strlen(extra_params)+1;
	
	// Calculate the length of the resulting URL (+1 for the null terminator)
	size_t url_len = base_len+params_len+1;

	// Allocate memory for the URL
	char *url = (char *)safe_alloc(url_len);
	if (url != NULL)
	{
		// Copy the base URL into the constructed URL
		strncpy(url, base_url, base_len);
		url[base_len] = '\0'; // Null-terminate the base URL in the new string
		
		// Concatenate the extra parameters
		strncat(url, extra_params, params_len);
		url[url_len - 1] = '\0'; // Ensure null termination at the end
	}
	return url;
}

/** Fetches a Bot struct of the intended responder to a command from MessageTag list
 * @param recv_mtags A MessageTag linked list to search for a responder
 * @returns A bot struct of the bot agent found in the MessageTag list
*/
Bot *fetch_responder(MessageTag *recv_mtags)
{
	MessageTag *m = find_mtag(recv_mtags, MTAG_RESPONDER);
	return (m) ? find_bot(m->value) : NULL;
}

/** Sets a new password for the account
 * @param client The client issuing the password change
 * @param account The name of the account to change in case it's an admin changing someones password for them or something
 * @param password The hash of the password (not the actual password itself) to update with.
 * @param responder The bot agent responsible for replying to this request after our callback later
 * @returns 1 on success, 0 on failure
*/
int set_user_password(Client *client, const char *account, const char *password, Bot *responder);

/** Send a static char help thing like ajoin_help */
static void display_halp(Client *client, char **helptext)
{
	for(; *helptext != NULL; helptext++)
		sendto_one(client, NULL, ":%s 304 %s :%s", me.name, client->name, *helptext);
}

/** The help output for /AJOIN */
static char *ajoin_help[] = {
	"***** AJOIN (Auto-Join) HELP *****",
	"-",
	"This is your own personal list of channels which you will be",
	"automatically joined to when you connect if you logged in,",
	"but will also be triggered if you login after you connected.",
	"Note: You must actually be in the channel you want to add to",
	"your auto-join list.",
	"You can type the command in either upper or lower-case, but ",
	"the examples below use upper-case for the purposes of this example",
	"-",
	"Syntax:",
	"	/AJOIN <add|del|list> [<channel>]",
	"-",
	"Examples:",
	"-",
	"Add the channel #PossumsOnly to your auto-join list:",
	"	/AJOIN add #PossumsOnly",
	"-",
	"Delete #BadChannel from your auto-join list",
	"	/AJOIN del #BadChannel",
	"-",
	"View your auto-join list:",
	"	/AJOIN list",
	"-",
	END_OF_HELP
};

ModuleHeader MOD_HEADER
= {
	"third/no-services",	/* Name of module */
	NOSERVICES_VERSION, /* Version */
	"Services functionality but without services", /* Short description of module */
	"Valware",
	"unrealircd-6",
};

/** Initialize the module! */
MOD_INIT()
{
	MessageTagHandlerInfo mtag;
	ModDataInfo mreq;

	MARK_AS_GLOBAL_MODULE(modinfo);
	freecfg();
	setcfg();

	memset(&mtag, 0, sizeof(mtag));
	mtag.is_ok = responder_is_ok;
	mtag.flags = MTAG_HANDLER_FLAGS_NO_CAP_NEEDED;
	mtag.name = "valware.uk/responder";
	if (!MessageTagHandlerAdd(modinfo->handle, &mtag))
	{
		config_error("Could not add MessageTag \"%s\". Please contact developer (Valware).", "valware.uk/responder");
		return MOD_FAILED;
	}
	memset(&mtag, 0, sizeof(mtag));
	mtag.is_ok = iso_lang_mtag_is_ok;
	mtag.flags = MTAG_HANDLER_FLAGS_NO_CAP_NEEDED;
	mtag.name = MTAG_ISO_LANG;
	if (!MessageTagHandlerAdd(modinfo->handle, &mtag))
	{
		config_error("Could not add MessageTag \"%s\". Please contact developer (Valware).", MTAG_ISO_LANG);
		return MOD_FAILED;
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.name = "language";
	mreq.free = language_free;
	mreq.serialize = language_serialize;
	mreq.unserialize = language_unserialize;
	mreq.type = MODDATATYPE_CLIENT;
	if (!ModDataAdd(modinfo->handle, mreq))
	{
		config_error("Could not add ModData for \"language\". Please contact developer (Valware).");
		return MOD_FAILED;
	}
	/** Account Registration cap key value
	 * eg "before-connect,email-required,custom-account-name"
	*/
	memset(&mreq, 0, sizeof(mreq));
	mreq.name = "regkeylist";
	mreq.free = regkeylist_free;
	mreq.serialize = regkeylist_serialize;
	mreq.unserialize = regkeylist_unserialize;
	mreq.type = MODDATATYPE_CLIENT;
	if (!ModDataAdd(modinfo->handle, mreq))
	{
		config_error("Could not add ModData for regkeylist. Please contact developer.");
		return MOD_FAILED;
	}
	
	memset(&mreq, 0, sizeof(mreq));
	mreq.name = "wants_to_drop_nick";
	mreq.free = wtdrop_free;
	mreq.serialize = wtdrop_serialize;
	mreq.unserialize = wtdrop_unserialize;
	mreq.type = MODDATATYPE_CLIENT;
	if (!(need_drop = ModDataAdd(modinfo->handle, mreq)))
	{
		config_error("Could not add ModData for account dropping. Please contact developer.");
		return MOD_FAILED;
	}
	
	memset(&mreq, 0, sizeof(mreq));
	mreq.name = "drop_key_md";
	mreq.free = dropkey_free;
	mreq.serialize = dropkey_serialize;
	mreq.unserialize = dropkey_unserialize;
	mreq.type = MODDATATYPE_CLIENT;
	if (!(drop_key_md = ModDataAdd(modinfo->handle, mreq)))
	{
		config_error("Could not add ModData for account dropping. Please contact developer.");
		return MOD_FAILED;
	}
	

	memset(&mreq, 0, sizeof(mreq));
	mreq.name = "sasl_auth_type";
	mreq.free = sat_free;
	mreq.serialize = sat_serialize;
	mreq.unserialize = sat_unserialize;
	mreq.type = MODDATATYPE_CLIENT;
	if (!(sasl_md = ModDataAdd(modinfo->handle, mreq)))
	{
		config_error("Could not add ModData for sasl_auth_type. Please contact developer.");
		return MOD_FAILED;
	}
	
	memset(&mreq, 0, sizeof(mreq));
	mreq.name = "need_login";
	mreq.free = need_login_free;
	mreq.serialize = need_login_serialize;
	mreq.unserialize = need_login_unserialize;
	mreq.type = MODDATATYPE_CLIENT;
	if (!(need_login = ModDataAdd(modinfo->handle, mreq)))
	{
		config_error("Could not add ModData for need_login. Please contact developer.");
		return MOD_FAILED;
	}
	memset(&mreq, 0, sizeof(mreq));
	mreq.name = "login_cred";
	mreq.free = login_cred_free;
	mreq.serialize = login_cred_serialize;
	mreq.unserialize = login_cred_unserialize;
	mreq.type = MODDATATYPE_CLIENT;
	if (!(login_cred = ModDataAdd(modinfo->handle, mreq)))
	{
		config_error("Could not add ModData for need_login. Please contact developer.");
		return MOD_FAILED;
	}
	/** Account Registration cap `draft/account-registration`
	*/
	ClientCapabilityInfo accreg_cap; 
	memset(&accreg_cap, 0, sizeof(accreg_cap));
	accreg_cap.name = REGCAP_NAME;
	accreg_cap.visible = accreg_capability_visible;
	accreg_cap.parameter = accreg_capability_parameter;
	if (!ClientCapabilityAdd(modinfo->handle, &accreg_cap, &CAP_ACCOUNTREGISTRATION))
	{
		config_error("Could not add CAP for draft/account-registration. Please contact developer.");
		return MOD_FAILED;
	}
	
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, noservices_configrun);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_CONNECT, 9999, noservices_hook_local_connect); // we want to be called after auto-oper and such
	HookAdd(modinfo->handle, HOOKTYPE_POST_LOCAL_NICKCHANGE, 0, noservices_hook_post_local_nickchange);
	HookAdd(modinfo->handle, HOOKTYPE_USERMSG, 9999, auto_translate);
	HookAddVoid(modinfo->handle, HOOKTYPE_NOSERV_CONNECT_AND_LOGIN, 0, do_ajoin); // custom hook baby

	/** Our API callback hooks */
	RegisterApiCallbackWebResponse(modinfo->handle, "register_account", register_account);
	RegisterApiCallbackWebResponse(modinfo->handle, "register_channel_callback", register_channel_callback);
	RegisterApiCallbackWebResponse(modinfo->handle, "ajoin_callback", ajoin_callback);
	RegisterApiCallbackWebResponse(modinfo->handle, "certfp_callback", certfp_callback);
	RegisterApiCallbackWebResponse(modinfo->handle, "connect_query_user_response", connect_query_user_response);
	RegisterApiCallbackWebResponse(modinfo->handle, "nick_account_enforce", nick_account_enforce);
	RegisterApiCallbackWebResponse(modinfo->handle, "setpassword_callback", setpassword_callback);
	RegisterApiCallbackWebResponse(modinfo->handle, "drop_callback", drop_callback);
	RegisterApiCallbackWebResponse(modinfo->handle, "ns_account_identify", ns_account_identify);
	RegisterApiCallbackWebResponse(modinfo->handle, "translate_callback", translate_callback);

	/** The commands that we are so nice as to add to the IRCd =] */
	CommandAdd(modinfo->handle, "SETLANG", cmd_setlang, 1, CMD_USER | CMD_UNREGISTERED);
	CommandAdd(modinfo->handle, "REGISTER", cmd_register, 3, CMD_USER | CMD_UNREGISTERED);
	CommandAdd(modinfo->handle, "CREGISTER",  cmd_cregister, 3, CMD_USER);
	CommandAdd(modinfo->handle, "IDENTIFY", cmd_identify, 3, CMD_USER);
	CommandAdd(modinfo->handle, "LOGOUT", cmd_logout, 0, CMD_USER);
	CommandAdd(modinfo->handle, "SALOGOUT", cmd_salogout, 1, CMD_OPER);
	CommandAdd(modinfo->handle, "AJOIN", cmd_ajoin, MAXPARA, CMD_USER);
	CommandAdd(modinfo->handle, "CERTFP", cmd_certfp, 2, CMD_USER);
	CommandAdd(modinfo->handle, "RELEASE", cmd_release, 2, CMD_USER);
	CommandAdd(modinfo->handle, "DROP", cmd_drop, 1, CMD_USER);
	CommandAdd(modinfo->handle, "SADROP", cmd_sadrop, 2, CMD_OPER);
	CommandAdd(modinfo->handle, "SETPASSWORD", cmd_setpassword, 2, CMD_USER);
	CommandAdd(modinfo->handle, "BOT", cmd_bot, 2, CMD_OPER);
	CommandAdd(modinfo->handle, "ACCESS", cmd_access, 5, CMD_USER);
	
	EventAdd(modinfo->handle, "nick_enforce", nick_enforce, NULL, 1000, 0);

	// A for Auto-translate
	UmodeAdd(modinfo->handle, 'A', UMODE_GLOBAL, 0, NULL, &UMODE_TRANSLATE);

	// Here, we take control of SASL but don't unload the original module because we
	// still wanna make use of the original event timer without duplicating code =]
	// so, remove the old ClientCapability for SASL
	ClientCapability *clicap = ClientCapabilityFindReal("sasl");
	ClientCapabilityDel(clicap);

	ClientCapabilityInfo cap;
	memset(&cap, 0, sizeof(cap));
	cap.name = "sasl";
	cap.visible = sasl_capability_visible;
	cap.parameter = sasl_capability_parameter;
	if (!(ClientCapabilityAdd(modinfo->handle, &cap, &CAP_SASL_OVR)))
		return MOD_FAILED;

	return MOD_SUCCESS;
}

int responder_is_ok(Client *client, const char *name, const char *value)
{
	Bot *bot = find_bot(value);
	if (bot && IsMe(client))
		return 1;
	return 0;
}

MOD_TEST()
{
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, noservices_configtest);
	return MOD_SUCCESS;
}
/* Is first run when server is 100% ready */
MOD_LOAD()
{
	CommandOverrideAdd(modinfo->handle, "AUTHENTICATE", 0, cmd_authenticate_ovr);
	CommandOverrideAdd(modinfo->handle, "PRIVMSG", 0, cmd_privmsg_ovr);
	CommandOverrideAdd(modinfo->handle, "NICK", 0, cmd_nick_ovr);
	return MOD_SUCCESS;
}

/* Called when module is unloaded */
MOD_UNLOAD()
{
	freecfg();
	free_bot_node();
	return MOD_SUCCESS;
}

void freecfg(void)
{
	safe_free(cfg.url);
	safe_free(cfg.key);
	safe_free(cfg.guest_nick);
	memset(&cfg, 0, sizeof(cfg));
}

void setcfg(void)
{
	safe_strdup(cfg.url, "");
	safe_strdup(cfg.key, "");
	safe_strdup(cfg.guest_nick, "Guest"); // default
	cfg.nick_enforce_timeout = 60; // 2 minutes to auth before nick gets changed
	cfg.bot_node = NULL;
}

// callback for registering accounts
void register_account(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;
	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "register", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	// result->memory contains all the data of the web response, in our case
	// we assume it is a JSON response, so we are going to parse it.
	// If you were expecting BINARY data then you can still use result->memory
	// but then have a look at the length in result->memory_len.
	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "register", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}
	const char *key;
	json_t *value;
	char *reason = NULL;
	char *code = NULL;
	char *account = NULL;
	Bot *bot = NULL;
	int success = 0;
	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "account"))
		{
			account = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "responder"))
		{
			bot = find_bot(json_string_value(value));
		}
	}

	if (client) // if our client is still online
	{
		// yay they registered
		if (success && account)
		{
			strlcpy(client->user->account, account, sizeof(client->user->account));
			sendto_one(client, NULL, "REGISTER SUCCESS %s %s", account, reason);
			bot_sendnotice(bot, client, "%s", reason);
			user_account_login(NULL, client);
			if (IsDead(client))
			{
				json_decref(result);
				return;
			}
			if (IsUser(client))
				RunHook(HOOKTYPE_NOSERV_CONNECT_AND_LOGIN, client, result);

			sendto_server(client, 0, 0, NULL, ":%s SVSLOGIN %s %s %s",
					me.name, "*", client->id, client->user->account);
			unreal_log(ULOG_INFO, "register", "ACCOUNT_REGISTRATION", NULL,
					"New account: \"$account\" registered to $client",
					log_data_string("account", client->user->account),
					log_data_string("client", client->name ? client->name : "a pre-connected user"));
		}
		else if (!success && code && account)
		{
			sendto_one(client, NULL, "FAIL REGISTER %s %s :%s", code, account, reason);
			bot_sendnotice(bot, client, "%s (%s: %s)", reason, code, account);
		}
	}

	json_decref(result);
}
/** Register accounts
 * /REGISTER <account name> <email> <password>
 */
CMD_FUNC(cmd_register)
{
	/* Responder */
	MessageTag *m = find_mtag(recv_mtags, MTAG_RESPONDER);
	Bot *bot = NULL;
	if (m)
		bot = find_bot(m->value);


	if (IsLoggedIn(client))
	{
		bot_sendnotice(bot, client, "You are already authenticated to an account.");
		sendto_one(client, NULL, ":%s FAIL REGISTER ALREADY_AUTHENTICATED %s :You are already authenticated to an account.", me.name, client->user->account);
		return;
	}
	if (BadPtr(parv[1]) || BadPtr(parv[2]) || BadPtr(parv[3]))
	{
		if (bot)
		{
			bot_sendnotice(bot, client, "Syntax: /msg %s REGISTER <account name> <email> <password>", bot->name);
		}
		sendto_one(client, NULL, ":%s FAIL REGISTER INVALID_PARAMS :Syntax: /REGISTER <account name> <email> <password>", me.name);
		return;
	}

	Client *stolen = find_user(parv[1], NULL);
	if (stolen && stolen != client)
	{
		bot_sendnotice(bot, client, "You may not register a nick that someone else is using.");
		sendto_one(client, NULL, ":%s FAIL REGISTER CANNOT_STEAL_NICK %s :You may not register a nick that someone else is using.", me.name, parv[1]);
		return;
	}

	TKL *nameban;
	nameban = my_find_tkl_nameban(parv[1]);
	if (nameban)
	{
		bot_sendnotice(bot, client, "You may not register that nick.");
		sendto_one(client, NULL, ":%s FAIL REGISTER BANNED_NICK %s :You may not register that nick.", me.name, parv[1]);
		return;
	}
	int len = strlen(parv[1]);
	if (len < 4)
	{
		bot_sendnotice(bot, client, "Your account name must be at least 4 characters long.");
		sendto_one(client, NULL, ":%s FAIL REGISTER INVALID_NAME %s :Your account name must be at least 4 characters long.", me.name, parv[1]);
		return;
	}

	/* protect against registering serv names lol */
	const char *target = "serv";
	int match = 1;
	// Compare the last 4 characters
	int i;
	for (i = 0; i < 4; i++)
	{
		char strChar = tolower(parv[1][len - 4 + i]); // Convert string character to lowercase
		char targetChar = tolower(target[i]);	// Convert target character to lowercase
		
		if (strChar != targetChar)
		{
			match = 0; // Characters don't match
			break;
		}
	}
	
	if (match)
	{
		bot_sendnotice(bot, client, "You may not register that nick.");
		sendto_one(client, NULL, ":%s FAIL REGISTER BANNED_NICK %s :You may not register that nick.", me.name, parv[1]);
		return;
	}
	if (BadPtr(cfg.url) || BadPtr(cfg.key)) // no api set? no registration
	{
		bot_sendnotice(bot, client, "Registration has not been configured on this server.");
		sendto_one(client, NULL, ":%s FAIL REGISTER TEMPORARILY_UNAVAILABLE %s :Registration has not been configured on this server.", me.name, parv[1]);
		return;
	}

	if ((!IsUser(client) && MyConnect(client)) && !cfg.register_before_connect)
	{
		bot_sendnotice(bot, client, "You must fully connect before registering an account.");
		sendto_one(client, NULL, ":%s FAIL REGISTER COMPLETE_CONNECTION_REQUIRED %s :You must fully connect before registering an account.", me.name, parv[1]);
		return;
	}
	char account[NICKLEN + 2];
	
	strlcpy(account, (!strcmp(parv[1],"*")) ? client->name : parv[1], iConf.nick_length + 1);
	// Account name stuff
	// accounts follow nick standard
	if (!cfg.register_custom_account && strcmp(parv[1],"*") != 0 && strcmp(parv[1], client->name))
	{
		bot_sendnotice(bot, client, "Your account name must be your nickname.");
		sendto_one(client, NULL, ":%s FAIL REGISTER ACCOUNT_NAME_MUST_BE_NICK %s :Your account name must be your nickname.", me.name, account);
		return;
	}
	if (!is_valid_nick(account))
	{
		bot_sendnotice(bot, client, "Your account name must be a valid nickname.");
		sendto_one(client, NULL, ":%s FAIL REGISTER BAD_ACCOUNT_NAME %s :Your account name must be a valid nickname.", me.name, account);
		return;
	}
	// Email stuff
	if (cfg.register_email_required // we need their email
		&& ((!strcmp(parv[2],"*")) // and they either didn't give it
		|| !IsValidEmail(parv[2]))) // or it was invalid
	{
		bot_sendnotice(bot, client, "Your email address is invalid.");
		sendto_one(client, NULL, ":%s FAIL REGISTER INVALID_EMAIL %s :Your email address is invalid.", me.name, parv[2]);
		return;
	}

	if (!check_password_strength_dalek(parv[3], cfg.password_strength_requirement))
	{
		bot_sendnotice(bot, client, "Your password is too weak. Please choose a stronger password.");
		sendto_one(client, NULL, ":%s FAIL REGISTER PASSWORD_TOO_WEAK %s :Your password is too weak. Please choose a stronger password", me.name, account);
		return;
	}

	const char *password_hash = NULL;
	
	if (!(password_hash = Auth_Hash(6, parv[3])))
	{
		bot_sendnotice(bot, client, "The hashing mechanism was not supported. Please contact an administrator");
		sendto_one(client, NULL, ":%s FAIL REGISTER SERVER_BUG %s :The hashing mechanism was not supported. Please contact an administrator.", me.name, parv[1]);
		return;
	}
	json_t *j;
	char *json_serialized;

	j = json_object();
	json_object_set_new(j, "method", json_string_unreal("register")); // we would like to register plz
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client trying to register
	json_object_set_new(j, "account", json_string_unreal(parv[1])); // account name they wanna register
	json_object_set_new(j, "email", json_string_unreal(parv[2])); // email they wanna use for registration (Can be "*")
	json_object_set_new(j, "password", json_string_unreal(password_hash)); // password
	if (bot)
		json_object_set_new(j, "responder", json_string_unreal(bot->name));

	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "registration", "BUG_SEREALIZE", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return;
	}
	json_decref(j);

	query_api("account", json_serialized, "register_account");
	add_fake_lag(client, 5000); // lag 'em for 5 seconds
}

// the callback for registering channels
void register_channel_callback(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;
	Channel *chan = NULL;
	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "chanreg", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	// result->memory contains all the data of the web response, in our case
	// we assume it is a JSON response, so we are going to parse it.
	// If you were expecting BINARY data then you can still use result->memory
	// but then have a look at the length in result->memory_len.
	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "chanreg", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}
	const char *key;
	json_t *value;
	char *reason = NULL;
	char *code = NULL;
	char *channel = NULL;
	Bot *bot = NULL;
	int success = 0;
	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "channel"))
		{
			channel = strdup(json_string_value(value));
			chan = find_channel(channel);
		}
		else if (!strcasecmp(key, "responder"))
		{
			bot = find_bot(json_string_value(value));
		}
	}

	if (client && chan && IsMember(client, chan) && IsLoggedIn(client)) // if our client is still online and our channel still exists and they're in it
	{
		// yay they registered
		if (success)
		{
			char *modes;
			const char *mode_args[3];

			mode_args[0] = "rq";
			mode_args[1] = client->name;
			mode_args[2] = 0;

			do_mode(chan, &me, NULL, 3, mode_args, 0, 0);// make this ACTUALLY sent by the server for the mode_is_ok check
			bot_sendnotice(bot, client, "Channel %s has been registered to your account.", chan->name);
			sendto_one(client, NULL, "CREGISTER SUCCESS %s :Channel %s has been registered to your account.", chan->name, chan->name);
			unreal_log(ULOG_INFO, "chanreg", "CHANNEL_REGISTRATION", NULL,
					"New channel: \"$chan\" registered to account \"$account\"",
					log_data_string("chan", channel),
					log_data_string("account", client->user->account));
			
		}
		else if (!success && code && channel)
		{
			special_send(bot, client, SR_FAIL, SR_FAIL, "CREGISTER",  code, channel, "%s", reason);
		}
	}

	free(reason);
	free(code);
	free(channel);
	json_decref(result);
}

/** Register a channel
 * /CREGISTER <channel>
 */
CMD_FUNC(cmd_cregister)
{
	/* Responder */
	MessageTag *m = find_mtag(recv_mtags, MTAG_RESPONDER);
	Bot *bot = NULL;
	if (m)
		bot = find_bot(m->value);

	
	Channel *chan;
	if (BadPtr(parv[1]))
	{
		special_send(bot, client, SR_FAIL, "CREGISTER",  "INVALID_PARAMS", "*", "Syntax: /msg %s CREGISTER <channel name>", bot->name);
		return;
	}
	if (!IsLoggedIn(client))
	{
		special_send(bot, client, SR_FAIL, "CREGISTER",  "NOT_LOGGED_IN", parv[1], "You must be logged into an account to register a channel.");
		return;
	}
	if (BadPtr(cfg.url) || BadPtr(cfg.key)) // no api set? no registration
	{
		special_send(bot, client, SR_FAIL, "CREGISTER",  "TEMPORARILY_UNAVAILABLE", parv[1], "Registration has not been configured on this server.");
		return;
	}

	chan = find_channel(parv[1]);
	if (!chan)
	{
		special_send(bot, client, SR_FAIL, "CREGISTER",  "INVALID_CHANNEL", parv[1], "Channel does not exist.");
		return;
	}
	if (has_channel_mode(chan, 'r'))
	{
		special_send(bot, client, SR_FAIL, "CREGISTER",  "ALREADY_REGISTERED", parv[1], "Channel is already registered.");
		return;
	}
	if (!IsMember(client, chan))
	{
		if (bot)
			bot_sendnotice(bot, client, "You are not on that channel (NOT_ON_CHANNEL: %s)", chan->name);
		else
			sendnumeric(client, ERR_NOTONCHANNEL, chan->name);
		return;
	}
	if (!check_channel_access(client, chan, "oaq"))
	{
		special_send(bot, client, SR_FAIL, "CREGISTER",  "NO_ACCESS", parv[1], "You need at least ops on that channel to register it.");
		return;
	}

	json_t *j;
	char *json_serialized;

	j = json_object();
	json_object_set_new(j, "method", json_string_unreal("register")); // we would like to register plz
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client trying to register
	json_object_set_new(j, "account", json_string_unreal(client->user->account)); // account of the user
	json_object_set_new(j, "channel", json_string_unreal(parv[1])); // name of the channel they want to register

	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "chanreg", "BUG_SEREALIZE", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return;
	}
	json_decref(j);
	query_api("channel", json_serialized, "register_channel_callback");
	add_fake_lag(client, 5000); // lag 'em for 5 seconds
}

int accreg_capability_visible(Client *client)
{
	return 1;
}

void regkeylist_free(ModData *m)
{
	safe_free(m->str);
}

const char *regkeylist_serialize(ModData *m)
{
	if (!m->str)
		return NULL;
	return m->str;
}

void regkeylist_unserialize(const char *str, ModData *m)
{
	safe_strdup(m->str, str);
}

void wtdrop_free(ModData *m)
{
	safe_free(m->str);
}

const char *wtdrop_serialize(ModData *m)
{
	if (!m->str)
		return NULL;
	return m->str;
}

void wtdrop_unserialize(const char *str, ModData *m)
{
	safe_strdup(m->str, str);
}

void dropkey_free(ModData *m)
{
	safe_free(m->str);
}

const char *dropkey_serialize(ModData *m)
{
	if (!m->str)
		return NULL;
	return m->str;
}

void dropkey_unserialize(const char *str, ModData *m)
{
	safe_strdup(m->str, str);
}

const char *sat_serialize(ModData *m)
{
	static char buf[32];
	if (m->i == 0)
		return NULL; /* not set */
	snprintf(buf, sizeof(buf), "%d", m->i);
	return buf;
}
void sat_free(ModData *m)
{
	m->i = 0;
}
void sat_unserialize(const char *str, ModData *m)
{
	m->i = atoi(str);
}
const char *need_login_serialize(ModData *m)
{
	static char buf[32];
	if (m->i == 0)
		return NULL; /* not set */
	snprintf(buf, sizeof(buf), "%d", m->i);
	return buf;
}
void need_login_free(ModData *m)
{
	m->i = 0;
}
void need_login_unserialize(const char *str, ModData *m)
{
	m->i = atoi(str);
}

void login_cred_unserialize(const char *str, ModData *m)
{
	safe_strdup(m->str, str);
}
const char *login_cred_serialize(ModData *m)
{
	if (!m->str)
		return NULL;
	return m->str;
}
void login_cred_free(ModData *m)
{
	safe_free(m->str);
}
const char *accreg_capability_parameter(Client *client)
{
	return moddata_client_get(&me, "regkeylist");
}

int noservices_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs)
{
	int errors = 0; // Error count
	int i; // Iterat0r
	ConfigEntry *cep; // To store the current variable/value pair etc, nested

	// Since we'll add a top-level block to unrealircd.conf, need to filter on CONFIG_MAIN lmao
	if (type != CONFIG_MAIN)
		return 0; // Returning 0 means idgaf bout dis

	// Check for valid config entries first
	if (!ce || !ce->name)
		return 0;

	// If it isn't our block, idc
	if (strcmp(ce->name, NO_SERVICES_CONF))
		return 0;

	// Loop dat shyte
	for (cep = ce->items; cep; cep = cep->next)
	{
		// Do we even have a valid name l0l?
		// This should already be checked by Unreal's core functions but there's no harm in having it here too =]
		if (!cep->name)
		{
			config_error("[no-services] %s:%i: blank %s item", cep->file->filename, cep->line_number, NO_SERVICES_CONF); // Rep0t error
			errors++; // Increment err0r count
			continue; // Next iteration imo tbh
		}

		if (!strcmp(cep->name, "api-url"))
		{
			if (cfg.got_url)
			{
				config_error("[no-services] %s:%i: duplicate %s::%s directive. Only one URL is supported at this time.", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
				errors++;
				continue;
			}

			cfg.got_url = 1;
			if (!strlen(cep->value))
			{
				config_error("[no-services] %s:%i: %s::%s must be non-empty", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
				errors++;
				continue;
			}

			continue;
		}

		if (!strcmp(cep->name, "api-key"))
		{
			if (cfg.got_key)
			{
				config_error("[no-services] %s:%i: duplicate %s::%s directive", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
				errors++;
				continue;
			}

			cfg.got_key = 1;
			if (!strlen(cep->value))
			{
				config_error("[no-services] %s:%i: %s::%s must be non-empty", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
				errors++;
				continue;
			}
			continue;
		}
		if (!strcmp(cep->name, "nick-enforcement-timeout"))
		{
			if (cfg.got_nick_enforcement_timeout)
			{
				config_error("[no-services] %s:%i: duplicate %s::%s directive.", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
				errors++;
				continue;
			}
			if (config_checkval(cep->value, CFG_TIME) <= 0)
			{
				config_error("[no-services] %s:%i: %s::%s must be a time string like '7d10m' or simply '20'", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
				errors++;
				continue;
			}
			cfg.got_nick_enforcement_timeout = 1;
			continue;
		}
		
		if (!strcmp(cep->name, "guest-nick"))
		{
			if (cfg.got_guest_nick)
			{
				config_error("[no-services] %s:%i: duplicate %s::%s directive.", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
				errors++;
				continue;
			}
			if (!strlen(cep->value))
			{
				config_error("[no-services] %s:%i: %s::%s must be non-empty", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
				errors++;
				continue;
			}
			cfg.got_guest_nick = 1;
			continue;
		}
		
		
		if (!strcmp(cep->name, "account-registration"))
		{
			ConfigEntry *cep2, *cep3;
			for (cep2 = cep->items; cep2; cep2 = cep2->next)
			{
				if (!cep2->name)
				{
					config_error("[no-services] %s:%i: blank %s::%s entry", cep2->file->filename, cep2->line_number, NO_SERVICES_CONF, cep->name); // Rep0t error
					errors++;
					continue;
				}

				if (!strcmp(cep2->name, "options"))
				{
					for (cep3 = cep2->items; cep3; cep3 = cep3->next)
					{
						if (!strcmp(cep3->name, "before-connect"))
						{
							if (cfg.register_before_connect)
							{
								config_warn("[no-services] %s:%i: duplicate %s::%s directive, ignoring.", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name);
								errors++;
								continue;
							}
							cfg.register_before_connect = 1;
							continue;
						}
						
						if (!strcmp(cep3->name, "custom-account-name"))
						{
							if (cfg.register_custom_account)
							{
								config_warn("[no-services] %s:%i: duplicate %s::%s directive, ignoring.", cep3->file->filename, cep3->line_number, NO_SERVICES_CONF, cep3->name);
								errors++;
								continue;
							}
							cfg.register_custom_account = 1;
							continue;
						}

						if (!strcmp(cep3->name, "email-required"))
						{
							if (cfg.register_email_required)
							{
								config_warn("[no-services] %s:%i: duplicate %s::%s directive, ignoring.", cep3->file->filename, cep3->line_number, NO_SERVICES_CONF, cep3->name);
								errors++;
								continue;
							}
							cfg.register_email_required = 1;
							continue;
						}
						config_warn("[no-services] %s:%i: unknown item %s::%s::%s::%s", cep3->file->filename, cep3->line_number, NO_SERVICES_CONF, cep->name, cep2->name, cep3->name); 
					}
					continue;
				}
				else if (!strcmp(cep2->name, "password-strength"))
				{
					if (cfg.got_password_strength_requirement)
					{
						config_warn("[no-services] %s:%i: duplicate %s::%s directive, ignoring.", cep2->file->filename, cep2->line_number, NO_SERVICES_CONF, cep2->name);
						errors++;
						continue;
					}
					cfg.got_password_strength_requirement = 1;
					continue;
				}
				config_warn("[no-services] %s:%i: unknown item %s::%s::%s", cep2->file->filename, cep2->line_number, NO_SERVICES_CONF, cep->name, cep2->name); // Rep0t warn if unknown directive =]
			}
			continue;
		}
		if (!strcmp(cep->name, "bot"))
		{
			ConfigEntry *cep2;
			if (!cep->items)
				continue;
			for (cep2 = cep->items; cep2; cep2 = cep2->next)
			{
				if (!is_valid_nick(cep2->name))
				{
					config_warn("[no-services] %s:%i: Invalid bot nick %s at %s::%s directive.", cep2->file->filename, cep2->line_number, cep2->name, NO_SERVICES_CONF, "bot");
					errors++;
					continue;
				}
				
			}
			continue;
		}

		// Anything else is unknown to us =]
		config_warn("[no-services] %s:%i: unknown item %s::%s", cep->file->filename, cep->line_number, NO_SERVICES_CONF, cep->name); // So display just a warning
	}
	if (!cfg.got_key || !cfg.got_url)
	{
		config_error("[no-services] You have not set your no-services block correctly.");
		errors++;
	}
	
	if (!cfg.got_password_strength_requirement)
	{
		config_warn("[no-services::account-registration::password-strength] You have not set a minimum password strength requirement. Defaulting to strongest possible strength.");
	}

	*errs = errors;
	return errors ? -1 : 1; // Returning 1 means "all good", -1 means we shat our panties
}

// "Run" the config (everything should be valid at this point)
int noservices_configrun(ConfigFile *cf, ConfigEntry *ce, int type)
{
	ConfigEntry *cep; // To store the current variable/value pair etc, nested

	// Since we'll add a top-level block to unrealircd.conf, need to filter on CONFIG_MAIN lmao
	if (type != CONFIG_MAIN)
		return 0; // Returning 0 means idgaf bout dis

	// Check for valid config entries first
	if (!ce || !ce->name)
		return 0;

	// If it isn't noservices, idc
	if (strcmp(ce->name, NO_SERVICES_CONF))
		return 0;

	// Loop dat shyte
	for (cep = ce->items; cep; cep = cep->next)
	{
		// Do we even have a valid name l0l?
		if (!cep->name)
			continue; // Next iteration imo tbh

		if (!strcmp(cep->name, "api-url"))
		{
			safe_strdup(cfg.url, cep->value);
			continue;
		}

		if (!strcmp(cep->name, "api-key"))
		{
			safe_strdup(cfg.key, cep->value);
			continue;
		}
		if (!strcmp(cep->name, "nick-enforce-timeout"))
		{
			cfg.nick_enforce_timeout = config_checkval(cep->value, CFG_TIME);
			continue;
		}
		if (!strcmp(cep->name, "guest-nick"))
		{
			safe_strdup(cfg.guest_nick, cep->value);
			continue;
		}
		if (!strcmp(cep->name, "account-registration"))
		{
			ConfigEntry *cep2, *cep3;
			for (cep2 = cep->items; cep2; cep2 = cep2->next)
			{
				if (!cep2->name)
					continue;

				if (!strcmp(cep2->name, "options"))
				{
					for (cep3 = cep2->items; cep3; cep3 = cep3->next)
					{
						if (!strcmp(cep3->name, "before-connect"))
						{
							cfg.register_before_connect = 1;
							continue;
						}
						
						if (!strcmp(cep3->name, "custom-account-name"))
						{
							cfg.register_custom_account = 1;
							continue;
						}

						if (!strcmp(cep3->name, "email-required"))
						{
							cfg.register_email_required = 1;
							continue;
						}
					}
				}
				else if (!strcmp(cep2->name, "password-strength"))
				{
					cfg.got_password_strength_requirement = 1;
					cfg.password_strength_requirement = atoi(cep2->value);
					continue;
				}
			}
		}

		/** Bots */
		if (!strcmp(cep->name, "bot"))
		{
			ConfigEntry *cep2;
			for (cep2 = cep->items; cep2; cep2 = cep2->next)
			{
				Bot *bot = AddBot(cep2->name);
				ConfigEntry *cep3;
				for (cep3 = cep2->items; cep3; cep3 = cep3->next)
				{
					if (!CommandExists(cep3->name))
					{
						config_warn("[no-services] %s:%i: Cannot add command '%s' to %s bot at %s::%s directive: Command exists.", cep3->file->filename, cep3->line_number, cep3->name, cep2->name, NO_SERVICES_CONF, "bot");
						continue;
					}
					if (BadPtr(cep3->value) || !strlen(cep3->value))
					{
						config_warn("[no-services] %s:%i: Cannot add command '%s' to %s bot at %s::%s directive: No helptext defined.", cep3->file->filename, cep3->line_number, cep3->name, cep2->name, NO_SERVICES_CONF, "bot");
						continue;
					}
					add_command_to_bot(bot, cep3->name, cep3->value);
				}
			}
			continue;
		}
	}
	if (!cfg.got_password_strength_requirement) // you have to explicitly enable 0 to work
		cfg.password_strength_requirement = 4;

	char *concatenated = (char *)safe_alloc(50);
	strcpy(concatenated, "");

	if (cfg.register_before_connect)
	{
			strcat(concatenated, "before-connect,");
	}
	if (cfg.register_custom_account)
		strcat(concatenated, "custom-account-name,");
	
	if (cfg.register_email_required)
		strcat(concatenated, "email-required");

	int len = strlen(concatenated);
	if (len > 0 && concatenated[len - 1] == ',')
	{
		concatenated[len - 1] = '\0';
	}
	moddata_client_set(&me, "regkeylist", concatenated);
	safe_free(concatenated);
	rehash_check_bline();
	return 1; // We good
}

/* This is the callback function for logging in */
void ns_account_identify(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;
	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "no-services", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	// result->memory contains all the data of the web response, in our case
	// we assume it is a JSON response, so we are going to parse it.
	// If you were expecting BINARY data then you can still use result->memory
	// but then have a look at the length in result->memory_len.
	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "no-services", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}
	const char *key;
	json_t *value;
	char *reason = '\0';
	char *code = NULL;
	char *account = NULL;
	char *password = NULL;
	Bot *bot = NULL;
	int success = 0;

	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);			
		}
		else if (!strcasecmp(key, "responder"))
		{
			bot = find_bot(json_string_value(value));
		}
		else if (!strcasecmp(key, "account"))
		{
			account = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "user"))
		{
			password = json_user_object_get_property(value, "password");
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
	}
	if (!client)
	{
		json_decref(result);
		return;
	}
	if (GetSaslType(client) != SASL_TYPE_EXTERNAL && !is_correct_password(client, password))
	{
		if (HasCapability(client, "sasl"))
				sendto_one(client, NULL, ":%s 904 %s :%s", me.name, account, "Invalid login credentials");
		if (bot)
			special_send(bot, client, SR_FAIL, "LOGIN", "BAD_LOGIN", NULL, "Invalid login credentials");
		add_fake_lag(client, 10000); // ten second penalty for bad logins
	}

	// otherwise their pasword was correct or they used EXTERNAL
	else if (success)
	{
		UnsetDropKey(client);
		strlcpy(client->user->account, account, sizeof(client->user->account));
		user_account_login(NULL, client);
		if (IsDead(client))
		{
			json_decref(result);
			return;
		}
		sendto_server(client, 0, 0, NULL, ":%s SVSLOGIN %s %s %s",
				me.name, "*", client->id, client->user->account);
		
		unreal_log(ULOG_INFO, "login", "ACCOUNT_LOGIN_SUCCESS", NULL,
				"$client successfully logged into account $account",
				log_data_string("account", client->user->account),
				log_data_string("client", !BadPtr(client->name) ? client->name : "A pre-connected user"));
		if (HasCapability(client, "sasl"))
			sendto_one(client, NULL, ":%s 903 %s :SASL authentication successful", me.name, account);
		if (IsUser(client))
			RunHook(HOOKTYPE_NOSERV_CONNECT_AND_LOGIN, client, result);

	}
	else if (bot)
	{
		if (HasCapability(client, "sasl"))
				sendto_one(client, NULL, ":%s 904 %s :%s", me.name, "*", "Invalid login credentials");
		if (bot)
			special_send(bot, client, SR_FAIL, "LOGIN", "BAD_LOGIN", NULL, "Invalid login credentials");
		add_fake_lag(client, 10000); // ten second penalty for bad logins
	}
	DelSaslType(client);
	UnsetPassword(client);
	json_decref(result);
}

/**
 * /IDENTIFY <account> <password>
*/
CMD_FUNC(cmd_identify)
{
	Bot *bot = fetch_responder(recv_mtags);
	if (BadPtr(parv[1]) || BadPtr(parv[2]))
	{
		special_send(bot, client, SR_FAIL, "IDENTIFY", "INVALID_PARAMS", NULL, "Syntax: /IDENTIFY <account> <password>");
		return;
	}
	json_t *j;
	char *json_serialized;

	j = json_object();
	json_object_set_new(j, "method", json_string_unreal("find")); // we would like to register plz
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client trying to register
	json_object_set_new(j, "account", json_string_unreal(parv[1])); // name of the user

	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "login", "BUG_SEREALIZE", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return;
	}
	safe_strdup(moddata_client(client, login_cred).str,parv[2]);
	json_decref(j);
	query_api("account", json_serialized, "ns_account_identify");
	add_fake_lag(client, 2000);
}

/** SASL */
CMD_OVERRIDE_FUNC(cmd_authenticate_ovr)
{

	Client *agent_p = NULL;
	json_t *j;
	char *json_serialized;

	/* Failing to use CAP REQ for sasl is a protocol violation. */
	if (!HasCapability(client, "sasl") || BadPtr(parv[1]))
		return;

	if ((parv[1][0] == ':') || strchr(parv[1], ' '))
	{
		sendnumeric(client, ERR_CANNOTDOCOMMAND, "AUTHENTICATE", "Invalid parameter");
		return;
	}

	if (strlen(parv[1]) > 400)
	{
		sendnumeric(client, ERR_SASLTOOLONG);
		return;
	}

	if (client->user == NULL)
		make_user(client);

	if ((!strcasecmp(parv[1], "PLAIN") || !strcasecmp(parv[1], "EXTERNAL")) && GetSaslType(client))
	{
		sendnotice(client, "[error] Previous AUTHENTICATE request still in progress.");
		return;
	}
	if (!strcasecmp(parv[1], "PLAIN"))
	{
		SetSaslType(client, SASL_TYPE_PLAIN);
		sendto_one(client, NULL, ":%s AUTHENTICATE +", me.name);
		return;
	}
	else if (!strcasecmp(parv[1], "EXTERNAL"))
		SetSaslType(client, SASL_TYPE_EXTERNAL);

	if (!GetSaslType(client) || GetSaslType(client) == SASL_TYPE_NONE)
		return;

	else if (GetSaslType(client) == SASL_TYPE_PLAIN)
	{
		j = json_object();
		char *account = (char *)safe_alloc(50), *password = (char *)safe_alloc(400);
		char buf[512];
		int n;
		n = b64_decode(parv[1], buf, sizeof(buf)-1);
		if (n <= 1)
		{
			json_decref(j);
			DelSaslType(client);
			return;
		}
		char *segments[3] = { NULL }; // Array to store segments
		int segmentIndex = 0;

		char *ptr = buf;
		segments[segmentIndex++] = ptr;

		while (segmentIndex < 3)
		{
			ptr++;
			if (*ptr == '\0')
			{
				segments[segmentIndex++] = ptr + 1;
			}
		}
		if (segmentIndex != 3)
		{
			json_decref(j);
			DelSaslType(client);
			return;
		}
		safe_strdup(account, segments[1]); // Assign the second segment to account
		safe_strdup(password, segments[2]); // Assign the third segment to password

		j = json_object();
		json_object_set_new(j, "method", json_string_unreal("find"));
		json_object_set_new(j, "uid", json_string_unreal(client->id));
		json_object_set_new(j, "account", json_string_unreal(account));
		safe_strdup(moddata_client(client, login_cred).str, password);

		json_serialized = json_dumps(j, JSON_COMPACT);
		if (!json_serialized)
		{
			DelSaslType(client);
			unreal_log(ULOG_WARNING, "login", "BUG_SEREALIZE", client,
					"Unable to serialize JSON request. Weird.");
			json_decref(j);
			return;
		}
		json_decref(j);
		query_api("account", json_serialized, "ns_account_identify");
		safe_free(account);
		safe_free(password);
	}
	else if (GetSaslType(client) == SASL_TYPE_EXTERNAL)
	{
		j = json_object();
		ModDataInfo *moddata;
		moddata = findmoddata_byname("certfp", MODDATATYPE_CLIENT);
		if (!moddata || !moddata_client(client, moddata).str)
		{
			json_decref(j);
			sendto_one(client, NULL, ":%s FAIL AUTHENTICATE NO_CERT :You don't have a Certificate Fingerprint to authenticate with.", me.name);
			DelSaslType(client);
			return;
		}
		json_object_set_new(j, "method", json_string_unreal("find by cert"));
		json_object_set_new(j, "uid", json_string_unreal(client->id));
		json_object_set_new(j, "cert", json_string_unreal(moddata_client(client, moddata).str));

		json_serialized = json_dumps(j, JSON_COMPACT);
		if (!json_serialized)
		{

			DelSaslType(client);
			unreal_log(ULOG_WARNING, "login", "BUG_SEREALIZE", client,
					"Unable to serialize JSON request. Weird.");
			json_decref(j);
			return;
		}
		json_decref(j);
		query_api("account", json_serialized, "ns_account_identify");
	}
}

int sasl_capability_visible(Client *client)
{
	/* Don't advertise 'sasl' capability if we are going to reject the
	 * user anyway due to set::plaintext-policy. This way the client
	 * won't attempt SASL authentication and thus it prevents the client
	 * from sending the password unencrypted (in case of method PLAIN).
	 */
	if (client && !IsSecure(client) && !IsLocalhost(client) && (iConf.plaintext_policy_user == POLICY_DENY))
		return 0;

	/* Similarly, don't advertise when we are going to reject the user
	 * due to set::outdated-tls-policy.
	 */
	if (IsSecure(client) && (iConf.outdated_tls_policy_user == POLICY_DENY) && outdated_tls_client(client))
		return 0;

	return 1;
}

const char *sasl_capability_parameter(Client *client)
{
	return "PLAIN,EXTERNAL"; /* NOTE: could still return NULL */
}

void ajoin_callback(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;

	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "ajoin", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "ajoin", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}

	Bot *bot = NULL;
	const char *key;
	json_t *value;
	char *reason = NULL;
	char *code = NULL;
	char *channel = NULL;
	int success = 0;
	char *type = NULL;
	int add = 0;
	int list = 0;
	char *channels_list = "\0";

	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "channel"))
		{
			channel = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "responder"))
		{
			bot = find_bot(json_string_value(value));
		}
		else if (!strcasecmp(key, "autojoin"))
		{
			const char *key2;
			json_t *value2;
			int i = 0;
			if (bot)
					bot_sendnotice(bot, client, "Displaying your Auto-Join list:");
			else
				sendto_one(client, NULL, ":%s NOTE AJOIN BEGIN_LIST :Displaying your Auto-Join list:", me.name);

			int ii = 1;
			json_object_foreach(value, key2, value2)
			{
				if (bot)
					bot_sendnotice(bot, client, "%d) %s", ii, json_string_value(value2));
				else
					sendto_one(client, NULL, ":%s NOTE AJOIN LIST %d :%s", me.name, ii, json_string_value(value2));
				++ii;
			}
			if (bot)
				bot_sendnotice(bot, client, "End of your Auto-Join list.");
			else
				sendto_one(client, NULL, ":%s NOTE AJOIN END_OF_LIST :End of autojoin list.", me.name);
		}
		else if (!strcasecmp(key, "type"))
		{
			type = strdup(json_string_value(value));
			if (!strcmp(type,"add"))
				add++;
			else if (!strcmp(type,"list"))
				list++;
		}
	}

	if (success && channel)
	{
		sendto_one(client, NULL, ":%s AJOIN %s SUCCESS %s :You have successfully %s %s %s your auto-join list.", me.name, (add) ? "ADD" : "DEL", channel, (add) ? "added" : "deleted", channel, (add) ? "to" : "from");
	}
	else if (channel && reason && code)
	{
		sendto_one(client, NULL, ":%s FAIL AJOIN %s :Could not %s %s your auto-join list: %s", me.name, channel, (add) ? "add" : "delete", (add) ? "to" : "from", reason);
	}
	
	json_decref(result);
}

CMD_FUNC(cmd_ajoin)
{
	Bot *bot = fetch_responder(recv_mtags);

	if (!IsLoggedIn(client))
	{
		sendto_one(client, NULL, ":%s FAIL AJOIN NOT_LOGGED_IN :You must be logged into an account to manage it.", me.name);
		return;
	}
	Channel *chan;
	// we already checked they're logged in
	if (BadPtr(parv[1]) || !strcasecmp(parv[1],"help"))
	{
		display_halp(client, ajoin_help);
		return;
	}

	json_t *j;
	char *json_serialized;
	j = json_object();

	if (!strcasecmp(parv[1],"add") && !BadPtr(parv[2]))
	{
		chan = find_channel(parv[2]);
		if (!chan || !IsMember(client, chan))
		{
			sendto_one(client, NULL, ":%s FAIL AJOIN NOT_ON_CHANNEL %s :You cannot add channels which you are not on to your auto-join list.", me.name, parv[2]);
			return;
		}
		json_object_set_new(j, "method", json_string_unreal("ajoin add")); // add the channel
	}

	else if (!strcasecmp(parv[1],"del") && !BadPtr(parv[2])) // we don't care if it exists or not
		json_object_set_new(j, "method", json_string_unreal("ajoin del")); // delete the channel
	else if (!strcasecmp(parv[1],"list"))
		json_object_set_new(j, "method", json_string_unreal("ajoin list")); // list the channels lmao
	
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client
	json_object_set_new(j, "account", json_string_unreal(client->user->account)); // ID of the client
	if (!BadPtr(parv[2]))
		json_object_set_new(j, "channel", json_string_unreal(parv[2])); // name of the user
	if (bot)
		json_object_set_new(j, "responder", json_string_unreal(bot->name));
	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "login", "BUG_SEREALIZE", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return;
	}
	json_decref(j);
	query_api("account", json_serialized, "ajoin_callback");
	add_fake_lag(client, 1000); // lag 'em for 5 seconds
}

CMD_FUNC(cmd_logout)
{
	Bot *bot = fetch_responder(recv_mtags);

	if (!IsLoggedIn(client))
	{
		special_send(bot, client, SR_FAIL, "LOGOUT", "NOT_LOGGED_IN", NULL, "You must be logged into an account to log out.");
		return;
	}
	strlcpy(client->user->account, "0", sizeof(client->user->account));
	if (client->umodes & UMODE_REGNICK)
	{
		if (MyUser(client))
			sendto_one(client, NULL, ":%s MODE %s :-r", client->name, client->name);
		client->umodes &= ~UMODE_REGNICK;
	}
	user_account_login(recv_mtags, client);
	sendto_server(client, 0, 0, NULL, ":%s SVSLOGIN * %s 0", me.id, client->name);
}

CMD_FUNC(cmd_salogout)
{
	Bot *bot = fetch_responder(recv_mtags);
	
	if (!IsOper(client))
		return;

	if (!ValidatePermissionsForPath("no-services::account::logout", client, NULL, NULL, NULL))
		return;

	if (BadPtr(parv[1]))
		return;

	Client *target = find_user(parv[1], NULL);
	if (!target)
	{
		sendnumeric(client, ERR_NOSUCHNICK, parv[1]);
		return;
	}
	if (target->umodes & UMODE_REGNICK)
	{
		if (MyUser(client))
			sendto_one(client, NULL, ":%s MODE %s :-r", client->name, client->name);
		client->umodes &= ~UMODE_REGNICK;
	}
	if (MyUser(target))
	{
		strlcpy(target->user->account, "0", sizeof(target->user->account));
		
		user_account_login(recv_mtags, client);
	}
	sendto_server(client, 0, 0, NULL, ":%s SVSLOGIN * %s 0", me.name, client->name);
	
}

int noservices_hook_local_connect(Client *client)
{
	if (!IsLoggedIn(client))
	{
		account_enforce_check(client);
		return 0;
	}
	connect_query_user(client);
	return 0;
}

void connect_query_user(Client *client)
{
	json_t *j;
	char *json_serialized;
	j = json_object();
	json_object_set_new(j, "method", json_string_unreal("find"));
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client
	json_object_set_new(j, "account", json_string_unreal(client->user->account)); // ID of the client
	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "noserviceslocalcon", "BUG_SEREALIZE", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return;
	}

	json_decref(j);
	add_fake_lag(client, 1000);
	query_api("account", json_serialized, "connect_query_user_response");
	return;
}

void connect_query_user_response(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;
	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "no-services-connect", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "no-services-connect", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}

	RunHook(HOOKTYPE_NOSERV_CONNECT_AND_LOGIN, client, result);
	
	json_decref(result);
}

// Search 
void do_ajoin(Client *client, json_t *result)
{
	const char *key;
	json_t *value;
	char *reason = NULL;
	char *code = NULL;
	char *account = NULL;
	int success = 0;
	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "user"))
		{
			const char *key2;
			json_t *value2;
			json_object_foreach(value, key2, value2)
			{
				if (!strcasecmp(key2, "meta"))
				{
					const char *key3;
					json_t *value3;
					json_object_foreach(value2, key3, value3)
					{
						const char *key4;
						json_t *value4;
						int is_ajoin = 0;
						json_object_foreach(value3, key4, value4)
						{
							if (!strcasecmp(key4, "meta_name") && !strcasecmp(json_string_value(value4),"ajoin"))
							{
								is_ajoin++;
								continue;
							}
							if (!strcasecmp(key4,"meta_value") && is_ajoin)
							{
								const char *parv[3];
								parv[0] = client->name;
								parv[1] = json_string_value(value4);
								parv[2] = NULL;
								do_cmd(client, NULL, "JOIN", 2, parv);
								is_ajoin = 0;
							}
							continue;
						}
						continue;
					}
					continue;
				}
				continue;
			}
			continue;
		}
	}
}

int certfp_helper(Client *client, int type, const char *param)
{
	json_t *j;
	char *json_serialized;
	j = json_object();
	if (type == CERTFP_ADD)
		json_object_set_new(j, "method", json_string_unreal("certfp add"));
	else if (type == CERTFP_DEL)
		json_object_set_new(j, "method", json_string_unreal("certfp del"));
	else if (type == CERTFP_LIST)
		json_object_set_new(j, "method", json_string_unreal("certfp list"));
	if (param)
		json_object_set_new(j, "cert", json_string_unreal(param));
	
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client
	json_object_set_new(j, "account", json_string_unreal(client->user->account)); // ID of the client
	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "noserviceslocalcon", "BUG_SEREALIZE", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return 0;
	}

	json_decref(j);
	query_api("account", json_serialized, "certfp_callback");
	add_fake_lag(client, 500); // lag 'em for 5 seconds
	return 1;
}
/** CertFP command
 * View or manage your saved Certificate Fingerprint list
 */
CMD_FUNC(cmd_certfp)
{
	if (!IsLoggedIn(client))
		sendnumeric(client, ERR_NEEDREGGEDNICK, "CERTFP");
		
	else if (!strcasecmp(parv[1],"add"))
	{
		ModDataInfo *moddata;
		moddata = findmoddata_byname("certfp", MODDATATYPE_CLIENT);
		if (!moddata || !moddata_client(client, moddata).str)
		{
			sendto_one(client, NULL, ":%s FAIL CERTFP NO_CERT :You don't have a Certificate Fingerprint to add.", me.name);
			return;
		}
		certfp_helper(client, CERTFP_ADD, moddata_client(client, moddata).str);
		return;
	}
	else if (!strcasecmp(parv[1],"list"))
		certfp_helper(client, CERTFP_LIST, NULL);
	
	else if (!strcasecmp(parv[1],"del"))
	{
		if (!parv[2])
		{
			sendto_one(client, NULL, ":%s FAIL CERTFP INVALID_PARAM :You did not specify a fingerprint to delete.", me.name);
			return;
		}
		certfp_helper(client, CERTFP_DEL, parv[2]);
	}
	add_fake_lag(client, 500);
}

void certfp_callback(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;
	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "no-services-connect", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "no-services-connect", "NOSERVICES_API_BAD_RESPONSE", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}

	const char *key;
	json_t *value;
	char *type = NULL;
	char *reason = NULL;
	char *code = NULL;
	char *cert = NULL;
	int success = 0;
	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);
		}
		if (!strcasecmp(key, "type"))
		{
			type = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "cert"))
		{
			cert = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "list"))
		{
			const char *key2;
			json_t *value2;
			json_object_foreach(value, key2, value2)
			{
				sendto_one(client, NULL, ":%s NOTE CERTFP LIST :%s", me.name, json_string_value(value2));
			}
			sendto_one(client, NULL, ":%s NOTE CERTFP END_OF_LIST :End of CertFP list", me.name);
		}
	}
	if (client && success && cert)
		sendto_one(client, NULL, ":%s NOTE CERTFP UPDATE_SUCCESSFUL %s :You have successfully updated your Certificate Fingerprint list.", me.name, cert);

	else if (client && !success && code && reason)
		sendto_one(client, NULL, ":%s FAIL CERTFP %s * :%s", me.name, code, reason);

	json_decref(result);
}

int noservices_hook_post_local_nickchange(Client *client, MessageTag *mtags, const char *oldnick)
{
	UnrequireLogin(client);
	// if they're already logged into that nick it's fine
	if (MyUser(client) && IsLoggedIn(client) && !strcasecmp(client->name, client->user->account))
	{
		return 0;
	}
	account_enforce_check(client);
	return 0;
}

void account_enforce_check(Client *client)
{
	json_t *j;
	char *json_serialized;
	j = json_object();
	json_object_set_new(j, "method", json_string_unreal("find"));
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client
	json_object_set_new(j, "account", json_string_unreal(client->name)); // see if that nick is registered
	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "no-services", "POST_LOCAL_NICK_CHANGE", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return;
	}

	json_decref(j);
	query_api("account", json_serialized, "nick_account_enforce");
}

void nick_account_enforce(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;
	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "no-services", "NICK_ENFORCE", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "no-services", "NICK_ENFORCE", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}

	const char *key;
	json_t *value;
	char *type = NULL;
	char *account = NULL;
	char *reason = NULL;
	char *code = NULL;
	char *cert = NULL;
	int success = 0;
	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);
		}
		if (!strcasecmp(key, "type"))
		{
			type = strdup(json_string_value(value));
		}
		if (!strcasecmp(key, "account"))
		{
			account = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
	}
	if (client && success && account && !strcasecmp(account, client->name))
	{ // if they're still online and have the bad nick
		sendto_one(client, NULL, ":%s NOTE * LOGIN_REQUIRED %s :You must login to that nick to use it.", me.name, client->name);
		RequireLogin(client);
	}
	// else no problem, they can use it
	else if (UserRequiresLogin(client))
		UnrequireLogin(client);

	json_decref(result);
}

EVENT(nick_enforce)
{
	Client *client;
	TKL *tkl;
	long long change_by = (long long)TStime() +  random_number(300,1800);
	list_for_each_entry(client, &lclient_list, lclient_node)
	{
		if (UserRequiresLogin(client) && (client->lastnick + cfg.nick_enforce_timeout) < TStime())
		{
			if (strcasecmp(client->name, client->user->account))
			{
				static char nick[NICKLEN];
				ircsnprintf(nick, sizeof(nick), "%s%d", cfg.guest_nick, random_number(1111,999999));

				// avoid nick collisions lol
				Client *lookup;
				while ((lookup = find_user(nick, NULL)) != NULL)
				{
					ircsnprintf(nick, sizeof(nick), "%s%d", cfg.guest_nick, random_number(1111,999999));
				}
				char mo[32], exp[32];
				ircsnprintf(mo, sizeof(mo), "%lld", (long long)TStime());
				ircsnprintf(exp, sizeof(exp), "%lld",  change_by);
				
				const char* tkllayer[10] = {
					me.name,		/*0  server.name */
					"+",			/*1  + = X-line add */
					"Q",			/*2  X-line type  */
					"H" ,		   /*3  user */
					client->name,		/*4  host */
					"no-services",   /*5  Who set the ban */
					exp,			/*6  expire_at; never expire */
					mo,		   /*7  set_at */
					"You must login to use that nick.",	/*8  default reason */
					NULL		/*9 Extra NULL element to prevent OOB */
				};
				
				cmd_tkl(&me, NULL, sizeof(tkllayer), tkllayer);

				// change their nick to
				const char *parv[3];
				parv[0] = me.name;
				parv[1] = strdup(nick);
				parv[2] = NULL;
				
				do_cmd(client, NULL, "NICK", 2, parv);

				Client *confirm = find_user(nick, NULL);
				if (!confirm) // unable to change nick due to too many nick changes. troublesome user. kill 'em I reckon
				{
					
					unreal_log(ULOG_INFO, "no-services", "NICK_ENFORCE_KILL", client,
									"$name!$ident@$host failed to identify too many times.",
									log_data_string("name", client->name),
									log_data_string("ident", client->user->username),
									log_data_string("host", client->user->realhost));
					dead_socket(client, "Server ended the connection.");
				}
				else unreal_log(ULOG_INFO, "no-services", "NICK_ENFORCE", client,
									"$name!$ident@$host failed to identify in time and has had their nick changed to be $nick",
									log_data_string("name", client->name),
									log_data_string("ident", client->user->username),
									log_data_string("host", client->user->realhost),
									log_data_string("nick", nick));
			}
			if (client)
				UnrequireLogin(client);
		}
	}
}

CMD_FUNC(cmd_release)
{
	if (!IsLoggedIn(client))
	{
		sendto_one(client, NULL, ":%s FAIL RELEASE NOT_LOGGED_IN :You are not logged in.", me.name);
		return;
	}

	TKL *nameban;
	nameban = find_tkl_nameban(TKL_NAME | TKL_GLOBAL, client->user->account, 1);
	if (!nameban)
	{
		sendto_one(client, NULL, ":%s FAIL RELEASE ACCOUNT_NOT_HELD :That account name is not on hold.", me.name);
		return;
	}
	sendnotice_tkl_del(client->name, nameban);
	
	sendto_server(NULL, 0, 0, NULL, ":%s TKL %c %c %c %s %s %lld %lld :%s", client->name,
			'-',
			TKL_NAME | TKL_GLOBAL,
			nameban->ptr.nameban->hold ? 'H' : '*',
			nameban->ptr.nameban->name,
			nameban->set_by,
			(long long)nameban->expire_at, (long long)nameban->set_at,
			nameban->ptr.nameban->reason);
	tkl_del_line(nameban);
	sendto_one(client, NULL, ":%s RELEASE SUCCESS ACCOUNT_RELEASED :Nick \"%s\" has been released. You may now use the nick.", me.name, client->user->account);
	
}

CMD_FUNC(cmd_drop)
{
	if (!IsLoggedIn(client))
	{
		sendto_one(client, NULL, ":%s FAIL DROP NOT_LOGGED_IN :You are not logged in.", me.name);
		return;
	}
	if (!(GetDropKey(client)))
	{
		SetDropKey(client, random_number(10000,99999));
		sendto_one(client, NULL, ":%s DROP * VERIFICATION_NEEDED %s :Please verify that you want to drop your account. This will delete your account and data. If you really want to do that, please type /drop %d", me.name, client->user->account, GetDropKey(client));
		return;
	}
	else if (!BadPtr(parv[1]))
	{
		const char *token = strdup(my_itoa(GetDropKey(client)));
		if (!strcmp(parv[1], token))
		{
			UnsetDropKey(client);
			do_account_drop(client->user->account, client->id);
			return;
		}
	}
	sendto_one(client, NULL, ":%s DROP * INCORRECT_CODE %s :The code you entered was incorrect.", me.name, client->user->account);	
}

/** Command /SADROP

*/
CMD_FUNC(cmd_sadrop)
{
	if (!IsOper(client) || BadPtr(parv[1]))
		return;

	if (!ValidatePermissionsForPath("no-services::account::drop", client, NULL, NULL, NULL))
		return;

	do_account_drop(parv[1], client->id);
}

/** Web API Call for dropping accounts */
void do_account_drop(const char *account, const char *callback_uid)
{
	json_t *j;
	char *json_serialized;
	j = json_object();
	json_object_set_new(j, "method", json_string_unreal("drop"));
	json_object_set_new(j, "uid", json_string_unreal(callback_uid)); // ID of the client
	json_object_set_new(j, "account", json_string_unreal(account)); // see if that nick is registered
	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "no-services", "POST_LOCAL_NICK_CHANGE", NULL,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return;
	}

	json_decref(j);
	query_api("account", json_serialized, "drop_callback");
}

/** /SETPASSWORD
	Allows a user to set their password
	parv[1] = new password
*/
CMD_FUNC(cmd_setpassword)
{
	Bot *bot = fetch_responder(recv_mtags);

	if (!IsLoggedIn(client))
	{
		special_send(bot, client, SR_FAIL, "SETPASSWORD", "NOT_LOGGED_IN", NULL, "You are not logged in.");
		return;
	}
	if (BadPtr(parv[1]))
		return;

	if (!check_password_strength_dalek(parv[1], cfg.password_strength_requirement))
	{
		special_send(bot, client, SR_FAIL, "SETPASSWORD", "PASSWORD_TOO_WEAK", client->user->account, "Your password is too weak. Please choose a stronger password");
		return;
	}

	const char *password_hash = NULL;
	
	if (!(password_hash = Auth_Hash(6, parv[1])))
	{
		special_send(bot, client, SR_FAIL, "SETPASSWORD", "SERVER_BUG", client->user->account, "The hashing mechanism was not supported. Please contact an administrator.");
		return;
	}

	// set their password
	set_user_password(client, client->user->account, password_hash, bot);
	
}

/** Wep API call for /SETPASSWORD */
int set_user_password(Client *client, const char *account, const char *password, Bot *responder)
{
	json_t *j;
	char *json_serialized;
	j = json_object();
	json_object_set_new(j, "method", json_string_unreal("set password"));
	json_object_set_new(j, "uid", json_string_unreal(client->id)); // ID of the client
	json_object_set_new(j, "account", json_string_unreal(account)); // see if that nick is registered
	json_object_set_new(j, "password", json_string_unreal(password));
	if (responder)
		json_object_set_new(j, "responder", json_string_unreal(responder->name));
	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "no-services", "SETPASSWORD", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return 0;
	}
	json_decref(j);
	query_api("account", json_serialized, "setpassword_callback");
	return 1;
}


/** Callback function for /SETPASSWORD */
void setpassword_callback(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;
	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "no-services", "ACCOUNT_DROP", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "no-services", "ACCOUNT_DROP", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}

	const char *key;
	json_t *value;
	char *account = NULL;
	char *reason = NULL;
	char *code = NULL;
	Bot *bot = NULL;
	int success = 0;
	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);
		}
		if (!strcasecmp(key, "account"))
		{
			account = strdup(json_string_value(value));
		}
		if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
		if (!strcasecmp(key, "responder"))
		{
			bot = find_bot(json_string_value(value));
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
	}
	if (success && client && account) // check all the clients everywhere and log them out if nessicelery
	{
		Client *cli_list;
		list_for_each_entry(cli_list, &client_list, client_node)
		{
			if (!IsUser(cli_list) || !IsLoggedIn(cli_list)) // if they're not logged in then skippem
				continue;

			if (strcasecmp(account, cli_list->user->account) != 0)
				continue;

			if (strcmp(cli_list->id,client->id) != 0)
			{
				if (MyUser(cli_list))	
					sendto_one(cli_list, NULL, ":%s NOTE SETPASSWORD PASSWORD_CHANGED %s :Your password has been changed by '%s'", me.name, account, client->name);
				else
					sendto_server(NULL, 0, 0, NULL, ":%s SREPLY %s N SETPASSWORD PASSWORD_CHANGED %s :Your password has been changed by %s", me.name, cli_list->id, cli_list->user->account, client->name);
			}
		}
		sendto_one(client, NULL, ":%s NOTE SETPASSWORD PASSWORD_CHANGED %s :Your password has been updated.", me.name, account);
	}
	else if (!success && client && reason)
	{
		sendto_one(client, NULL, ":%s FAIL SETPASSWORD %s :%s.", me.name, code, reason);
	}

	json_decref(result);
}

void drop_callback(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	Client *client = NULL;
	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "no-services", "ACCOUNT_DROP", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "no-services", "ACCOUNT_DROP", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}

	const char *key;
	json_t *value;
	char *account = NULL;
	char *reason = NULL;
	char *code = NULL;
	int success = 0;
	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "uid"))
		{
			client = find_client(json_string_value(value), NULL);
		}
		if (!strcasecmp(key, "account"))
		{
			account = strdup(json_string_value(value));
		}
		if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
	}
	if (success && client && account) // check all the clients everywhere and log them out if nessicelery
	{
		Client *cli_list;
		list_for_each_entry(cli_list, &client_list, client_node)
		{
			if (!IsUser(cli_list) || !IsLoggedIn(cli_list)) // if they're not logged in then skippem
				continue;
			if (strcasecmp(account, cli_list->user->account) != 0)
				continue;

			if (MyUser(cli_list))
			{
				strlcpy(cli_list->user->account, "0", sizeof(cli_list->user->account));
				user_account_login(NULL, cli_list);
			
				sendto_one(cli_list, NULL, ":%s NOTE * ACCOUNT_DROPPED %s :You have been logged out because this account (%s) has been dropped by %s",
										me.name, account, account, client->name);

			} else {
				sendto_one(cli_list, NULL, ":%s SREPLY %s %s * %s %s :You have been logged out because this account (%s) has been dropped by %s",
						me.name, cli_list->id, "N", "ACCOUNT_DROPPED", account, account, client->name);
			}
			
			sendto_server(client, 0, 0, NULL, ":%s SVSLOGIN * %s 0", me.name, cli_list->id);
		}
	}
	else if (!success && client && reason && code)
	{
		sendto_one(client, NULL, ":%s FAIL DROP %s :Unable to drop account: %s.", me.name, code, reason);
	}

	json_decref(result);
}

CMD_FUNC(cmd_bot)
{
	if (BadPtr(parv[1]))
		return;

	if (!strcasecmp(parv[1],"add") && !BadPtr(parv[2]))
	{
		Bot *bot = find_bot(parv[2]);
		if (bot)
		{
			sendnotice(client, "A bot with that name already exists");
			return;
		}
		if (!is_valid_nick(parv[2]))
		{
			sendnotice(client, "Invalid bot nick");
			return;
		}
		AddBot(parv[2]);
	}
	if (!strcasecmp(parv[1],"del") && !BadPtr(parv[2]))
	{
		DelBot(parv[2]);
	}
	else if (!strcasecmp(parv[1], "list"))
	{
		Bot *currentBot;
		if (cfg.bot_node)
			sendnotice(client, "\002\035Listing available server bots:\002\035");
		else
		{
			sendnotice(client, "\002No available server bots\002");
			return;
		}
		int i = 1; 
		for (currentBot = cfg.bot_node; currentBot != NULL; currentBot = currentBot->next)
		{
			bot_sendnotice(currentBot, client, "\035%d)\035 %s", i, currentBot->name);
			i++;
		}
	}
}

CMD_OVERRIDE_FUNC(cmd_privmsg_ovr)
{
	Bot *bot;
	if (BadPtr(parv[1]))
	{
		CALL_NEXT_COMMAND_OVERRIDE();
		return;
	}
	bot = find_bot(parv[1]);
	if (!bot)
	{
		CALL_NEXT_COMMAND_OVERRIDE();
		return;
	}

	// it's definitely for us
	if (!strcasecmp(parv[2], "help"))
	{
		BotCommand *cmd = bot->cmdslist;
		bot_sendnotice(bot, client, "Showing all available commands for %s:", bot->name);
		bot_sendnotice(bot, client, " ");
		while (cmd)
		{
			char spaces[20] = "";
			int i = 0;
			int difference = sizeof(spaces) - strlen(cmd->command);
			for (; i < difference; i++)
				strlcat(spaces," ", sizeof(spaces));

			
			bot_sendnotice(bot, client, "%s%s%s", cmd->command, spaces, cmd->helptext);
			cmd = cmd->next;
		}
		bot_sendnotice(bot, client, " ");
		bot_sendnotice(bot, client, "End of commands list for %s", bot->name);
		return;
	}
	
	char *parvdup = strdup(parv[2]);
	
	const char *parx[MAXPARA];
	parx[0] = NULL;
	int i = 1;

	char* token = strtok(parvdup, " ");
	
	RealCommand *realcmd = find_command_simple(token);

	if (!realcmd || !BotHasCommand(bot, realcmd->cmd))
	{
		bot_sendnotice(bot, client, "Unrecognised command: \"%s\"", uppercaseString(token));
		free(parvdup);
		return;
	}
	
	char remnants[MAXLINELENGTH] = "";
	for (token = strtok(NULL, " "); token != NULL;token = strtok(NULL, " "))
	{
		if (i < realcmd->parameters)
		{
			parx[i] = token;
			i++;
		}
		else
		{
			strcat(remnants, token);
			strcat(remnants, " ");
		}
	}

	if (strlen(remnants) > 1)
	{
		remnants[strlen(remnants) - 1] = '\0'; // drop that last space
		parx[i] = remnants;
	}
	else
		parx[i] = "";
	parx[i + 1] = NULL;

	mtag_add_responder(&recv_mtags, bot);

	// ALL SET VALWARE M'GIRL
	do_cmd(client, recv_mtags, realcmd->cmd, realcmd->parameters, parx);
	free(parvdup);
}

CMD_OVERRIDE_FUNC(cmd_nick_ovr)
{
	if ((parc < 2) || BadPtr(parv[1]))
	{
		CALL_NEXT_COMMAND_OVERRIDE();
		return;
	}

	Bot *bot = find_bot(parv[1]);
	if (bot)
	{
		sendnumeric(client, ERR_ERRONEUSNICKNAME, bot->name, "Reserved for internal IRCd purposes");
		return;
	}
	CALL_NEXT_COMMAND_OVERRIDE();
}

/** Set preferred translation language
	parv[1] = language code
*/
CMD_FUNC(cmd_setlang)
{
	if (BadPtr(parv[1]) || !isValidISOLanguageCode(parv[1]))
	{
		sendto_one(client, NULL, ":%s FAIL SETLANG INVALID_ISO_LANG * :Please specify a valid ISO language code, for example /SETLANG en-GB", me.name);
		return;
	}
	SetLanguage(client, parv[1]);
	sendnotice(client, "You have updated your chosen incoming translation language to be \"%s\"", parv[1]);
}


/** Translation callback function */
void translate_callback(OutgoingWebRequest *request, OutgoingWebResponse *response)
{
	json_t *result;
	json_error_t jerr;
	if (response->errorbuf || !response->memory)
	{
		unreal_log(ULOG_INFO, "no-services", "TRANSLATE_CALLBACK", NULL,
					"Error while trying to check $url: $error",
					log_data_string("url", request->url),
					log_data_string("error", response->errorbuf ? response->errorbuf : "No data (body) returned"));
		return;
	}

	result = json_loads(response->memory, JSON_REJECT_DUPLICATES, &jerr);
	if (!result)
	{
		unreal_log(ULOG_INFO, "no-services", "TRANSLATE_CALLBACK", NULL,
					"Error while trying to check $url: JSON parse error",
					log_data_string("url", request->url));
		return;
	}

	const char *key;
	json_t *value;
	char *account = NULL;
	char *reason = NULL;
	char *code = NULL;
	char *translated_text = NULL;
	int success = 0;
	char *detected_lang = NULL;
	Client *from = NULL, *to = NULL;

	json_object_foreach(result, key, value)
	{
		if (!strcasecmp(key, "from"))
		{
			from = find_client(json_string_value(value), NULL);
		}
		if (!strcasecmp(key, "to"))
		{
			to = find_client(json_string_value(value), NULL);
		}
		if (!strcasecmp(key, "source"))
		{
			detected_lang = strdup(json_string_value(value));
		}
		if (!strcasecmp(key, "text"))
		{
			translated_text = strdup(json_string_value(value));
		}
		if (!strcasecmp(key, "code"))
		{
			code = strdup(json_string_value(value));
		}
		else if (!strcasecmp(key, "success") || !strcasecmp(key, "error"))
		{
			if (!strcasecmp(key, "success"))
			{
				success = 1;
			}
			reason = strdup(json_string_value(value));
		}
	}
	if (success && from && to && translated_text && IsAutoTranslate(to))
	{
		// only send to them if we couldn't auto-detect their language, or if we know the auto-detected language is already their language
		if ((!detected_lang && GetLanguage(to)) || ((detected_lang && GetLanguage(to)) && !strcasestr(GetLanguage(to), detected_lang)))
			sendto_one(to, NULL, ":%s!%s@%s PRIVMSG %s :%s", from->name, from->user->username, from->user->cloakedhost, to->name, translated_text);
	}

	json_decref(result);
}

/** HOOKTYPE_USERMSG
	This will automatically translate incoming messages to your chosen language
*/
int auto_translate(Client *from, Client *to, MessageTag *mtags, const char *text, SendType sendtype)
{
	/** Only translate if the following conditions are met:
	 * - Target user is our local user
	 * - Target has auto-translation on
	 * - Target has specified a language to translate to
	 * - Message is a privmsg (not notice)
	 */
	if (!MyUser(to) || !has_user_mode(to, 'A') || !GetLanguage(to) || sendtype != SEND_TYPE_PRIVMSG)
		return 0;

	MessageTag *m = find_mtag(mtags, "msgid");
	if (!m)
	{
		return 0;
	}
	json_t *j;
	char *json_serialized;
	j = json_object();
	
	json_object_set_new(j, "id", json_string_unreal(m->value)); // ID of the client
	json_object_set_new(j, "target_language", json_string_unreal(GetLanguage(to))); // see if that nick is registered
	json_object_set_new(j, "text", json_string_unreal(text));
	json_object_set_new(j, "from", json_string_unreal(from->id));
	json_object_set_new(j, "to", json_string_unreal(to->id));

	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "no-services", "AUTOTRANSLATE", from,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return 0;
	}
	json_decref(j);
	query_api("translate", json_serialized, "translate_callback");
	return 0;
}


CMD_FUNC(cmd_access)
{
	Client *target;
	MessageTag *m = find_mtag(recv_mtags, MTAG_RESPONDER);
	Bot *bot = NULL;
	const char *type = NULL, *level = NULL;
	const char *account_to_modify = NULL;

	if (m)
		bot = find_bot(m->value);

	if (BadPtr(parv[1]) || BadPtr(parv[2]) || BadPtr(parv[3]))
	{
		special_send(bot, client, SR_FAIL, "ACCESS", "NEED_MORE_PARAMS", NULL, "Syntax: ACCESS <chan> <add|del|list> [<account> [<level]]");
		return;
	}
	if (!BadPtr(parv[3]))
		type = parv[3];
	if (!BadPtr(parv[4]))
		account_to_modify = parv[4];
	if (!BadPtr(parv[5]))
		level = parv[5];

	json_t *j;
	char *json_serialized;
	j = json_object();
	
	json_object_set_new(j, "channel", json_string_unreal(parv[1]));
	json_object_set_new(j, "id", json_string_unreal(client->id));
	json_object_set_new(j, "method", json_string_unreal("access")); // ID of the client
	json_object_set_new(j, "type", json_string_unreal(type)); // see if that nick is registered
	if (account_to_modify)
		json_object_set_new(j, "account_to_modify", json_string_unreal(account_to_modify));
	if (level)
		json_object_set_new(j, "level", json_string_unreal(level));
	if (bot)
		json_object_set_new(j, "responder", json_string_unreal(bot->name));
	json_serialized = json_dumps(j, JSON_COMPACT);
	if (!json_serialized)
	{
		unreal_log(ULOG_WARNING, "no-services", "ACCESS", client,
				"Unable to serialize JSON request. Weird.");
		json_decref(j);
		return;
	}
	json_decref(j);
	query_api("channel", json_serialized, "access_callback");
}
