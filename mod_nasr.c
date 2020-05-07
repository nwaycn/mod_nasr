/*
License:GPL 2
Auth: Mr hao li
email: lihao@nway.com.cn
*/
#include "switch.h"
#include "switch_ivr.h"
#include "switch_types.h"
#define MORE_THAN_FS_VER1_6 

//__attribute__ ((visibility("default")))
SWITCH_MODULE_LOAD_FUNCTION(mod_nasr_load);

//__attribute__ ((visibility("default")))
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_nasr_shutdown);

//__attribute__ ((visibility("default")))
SWITCH_MODULE_DEFINITION(mod_nasr, mod_nasr_load, mod_nasr_shutdown, NULL);

//int running =1;
static struct {
	switch_memory_pool_t *pool;
	switch_mutex_t *mutex;
	unsigned int fs_ver;   //fs版本
	 
	int debug;
	char* log_dir;//日志路径 
	int log_level;
	char* grammar;
	char* asr_name;
} globals;

typedef struct nasr_helper {
	 
	switch_core_session_t *session;
	switch_core_session_t *other_session;
	switch_audio_resampler_t *resampler;
	switch_asr_handle_t *ah;
	 
}nasr_helper;

SWITCH_DECLARE(switch_status_t) switch_ivr_stop_ns_session(switch_core_session_t *session, nasr_helper *rh, switch_media_bug_t *bug);

SWITCH_DECLARE(char *) switch_uuid_str(char *buf, switch_size_t len)
{
	switch_uuid_t uuid;

	if (len < (SWITCH_UUID_FORMATTED_LENGTH + 1)) {
		switch_snprintf(buf, len, "INVALID");
	} else {
		switch_uuid_get(&uuid);
		switch_uuid_format(buf, &uuid);
	}

	return buf;
}

static switch_bool_t nway_nasr_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type)
{
	switch_core_session_t *session = switch_core_media_bug_get_session(bug);
	switch_channel_t *channel = switch_core_session_get_channel(session);
	ns_helper *rh = (nasr_helper *) user_data;
	switch_event_t *event;
	switch_frame_t *nframe;
	switch_size_t len = 0;
	 
	switch_codec_t* raw_codec = NULL;
	switch_codec_implementation_t read_impl ;
	int mask = switch_core_media_bug_test_flag(bug, SMBF_MASK);
	unsigned char null_data[SWITCH_RECOMMENDED_BUFFER_SIZE] = {0};

	int16_t *read_data;
	int read_samples;
	switch_status_t status;
 
	switch_core_session_get_read_impl(session, &read_impl);
 
    
	int channels = read_impl.number_of_channels;
 
	 
	switch (type) {
	case SWITCH_ABC_TYPE_INIT:
		{
		
		}
		break;
	case SWITCH_ABC_TYPE_TAP_NATIVE_READ:
		{
			
		}
		break;
	case SWITCH_ABC_TYPE_TAP_NATIVE_WRITE:
		{
			
		}
		break;
	case SWITCH_ABC_TYPE_CLOSE:
		{
    		switch_ivr_stop_nasr_session(session,rh,bug); 
			return SWITCH_FALSE;
		}
		
		break;
	case SWITCH_ABC_TYPE_READ_PING:
		 
		break;
	case SWITCH_ABC_TYPE_READ:
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "SWITCH_ABC_TYPE_READ \n");
		break;
	case SWITCH_ABC_TYPE_WRITE_REPLACE:
		{
			switch_frame_t *wframe = switch_core_media_bug_get_write_replace_frame(bug);
			
			switch_core_media_bug_set_write_replace_frame(bug, wframe);
		}
		break;
       
	case SWITCH_ABC_TYPE_READ_REPLACE:
		{
			switch_frame_t *rframe=NULL;
			
			
			rframe = switch_core_media_bug_get_read_replace_frame(bug);
			
			
			switch_core_media_bug_set_read_replace_frame(bug, rframe);
		}
		break;
	 
	default:
		break;
	}
	return SWITCH_TRUE;


}


SWITCH_DECLARE(switch_status_t) nway_nasr_session(switch_core_session_t *session )
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	const char *p;
	const char *vval;
	switch_media_bug_t *bug;
	switch_status_t status;
	time_t to = 0;
	switch_media_bug_flag_t flags = SMBF_NO_PAUSE|SMBF_READ_REPLACE|SMBF_WRITE_REPLACE;
	//SMBF_READ_PING|SMBF_READ_STREAM | SMBF_WRITE_STREAM |SMBF_TAP_NATIVE_READ |SMBF_TAP_NATIVE_WRITE|SMBF_NO_PAUSE|SMBF_READ_REPLACE;
	uint8_t channels;
	switch_codec_implementation_t read_impl ;
	nasr_helper *rh = NULL;

	switch_codec_t raw_codec  ;
	for (; ;) {
		
		rh = (nasr_helper*)switch_core_session_alloc(session, sizeof(*rh));
		
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE, "this call answer state:%d \n",switch_core_session_count());
		
		if (!switch_channel_media_up(channel) ) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Can not da session.  Media not enabled on channel\n");
			break;
		}
		if ( !switch_core_session_get_read_codec(session)){
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Can got codec of session\n");
			break;
		}

		switch_core_session_get_read_impl(session, &read_impl);
		rh->session= session;

		switch_assert(session);
		switch_assert(channel);
		
		switch_caller_profile_t *caller_profile=NULL;
		caller_profile = switch_channel_get_caller_profile(channel);
		switch_assert(caller_profile);
		if (caller_profile){
			rh->destination_number = switch_core_strdup(globals.pool,caller_profile->destination_number);	
			rh->gateway_name = 	switch_core_strdup(globals.pool,switch_channel_get_variable(channel, "sip_gateway_name"));
		}
		
		rh->resampler = NULL;
		if (read_impl.actual_samples_per_second != 8000) {

			if (switch_resample_create(&rh->resampler,
				read_impl.actual_samples_per_second,
				8000,
				read_impl.samples_per_packet, SWITCH_RESAMPLE_QUALITY, 1) != SWITCH_STATUS_SUCCESS) {

					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Unable to create resampler!\n");

					break;

			}
		}
	
		int tflags = 0;
		
	 
		const char* uuid;
		if ((uuid = switch_channel_get_partner_uuid(channel))) {

			if ((rh->other_session = switch_core_session_locate(uuid))){
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE, "get other session successed\n" );
			}else{
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE, "get other session failed\n" );
			}
		}
		int sampleRate = read_impl.actual_samples_per_second;
		
		 
		switch_channel_set_private(channel,switch_channel_get_uuid(channel),bug);
		if ((status = switch_core_media_bug_add(session, "start_nasr", NULL,
												nway_ns_callback, rh, to, flags, &bug)) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Error adding media bug for nasr\n" );
			
			
		
			return status;
		}
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "added media bug for nasr\n" );
	 
		return SWITCH_STATUS_SUCCESS;
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "exit nasr when wrong\n" );
	 
    switch_core_session_reset(session, SWITCH_FALSE, SWITCH_TRUE);
	return SWITCH_STATUS_FALSE;
}

static switch_status_t load_config(void)
{
	char *cf = "nasr.conf";
	switch_xml_t cfg, xml = NULL, param, settings;
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	char uuid_str[SWITCH_UUID_FORMATTED_LENGTH + 1];
    switch_uuid_str(uuid_str, sizeof(uuid_str));
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, uuid_str);
 
	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", cf);
		status = SWITCH_STATUS_FALSE;
		goto done;
	}
 
	if ((settings = switch_xml_child(cfg, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");
			
			if (!strcasecmp(var, "log_dir")) {
				if (!zstr(val) && switch_is_file_path(val)) {
					globals.log_dir = switch_core_strdup(globals.pool, val);
					 
				}
			}
			if (!strcasecmp(var, "grammar")) {
				if (!zstr(val) && switch_is_file_path(val)) {
					globals.grammar = switch_core_strdup(globals.pool, val);
					 
				}
			}
			if (!strcasecmp(var, "asr_name")) {
				if (!zstr(val) && switch_is_file_path(val)) {
					globals.asr_name = switch_core_strdup(globals.pool, val);
					 
				}
			}

		}
	}

	 
  done: 
	if (xml) {
		switch_xml_free(xml);
	}

	return status;
}


SWITCH_STANDARD_APP(nasr_stop_session_function)
{
   switch_media_bug_t *bug;
   switch_channel_t *channel = switch_core_session_get_channel(session);

   if (channel && (bug = switch_channel_get_private(channel, switch_channel_get_uuid(channel)))) {
		switch_core_media_bug_remove(session, &bug);	
	}
}
SWITCH_DECLARE(switch_status_t) switch_ivr_stop_nasr_session(switch_core_session_t *session, struct ns_helper *rh, switch_media_bug_t *bug)
{
	 
	if (session == NULL){
	}else{
		switch_channel_t *channel = switch_core_session_get_channel(session);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "removed media bug:%s\n",rh->destination_number); 
		if ( switch_channel_down_nosig(channel)  )
		{	
		}
	}
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_STANDARD_APP(nasr_session_function)
{
	nway_nasr_session(session);
}
 
SWITCH_MODULE_LOAD_FUNCTION(mod_nasr_load)
{
	switch_application_interface_t *app_interface;
	 
	memset(&globals, 0, sizeof(globals));
	globals.pool = pool;
	 
	switch_api_interface_t *api_interface;

	switch_mutex_init(&globals.mutex, SWITCH_MUTEX_NESTED, globals.pool);

	unsigned int major = atoi(switch_version_major());
	unsigned int minor = atoi(switch_version_minor());
	unsigned int micro = atoi(switch_version_micro());

	globals.fs_ver = major << 16;
	globals.fs_ver |= minor << 8;
	globals.fs_ver |= micro << 4;
		
	load_config();

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	
	SWITCH_ADD_APP(app_interface, "start_nasr", "nway asr start", "nasr", nasr_session_function, "", SAF_MEDIA_TAP);
	SWITCH_ADD_APP(app_interface, "stop_nasr", "nway asr stop", "ns", nasr_stop_session_function, "", SAF_NONE);
		
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "module ns loaded\n");
	return SWITCH_STATUS_SUCCESS;

   
}
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_nasr_shutdown)
{
	if (globals.mutex)
	 	switch_mutex_destroy(globals.mutex);	 
	return SWITCH_STATUS_SUCCESS;
}