#include "KWebDavClient.h"
#include "kselector_manager.h"
#include "KDefer.h"
#include "kfiber.h"
#include "KDechunkEngine.h"

#define LOCKED_FILE_CONTENT "lock-test"
#define DAV_PREFIX_DIR "/dav"
#define DAV_AUTH_USER "test"
#define DAV_AUTH_PASSWD "test"
#define test_assert(x) test_assert2(x,__FILE__,__LINE__)
static int total_passed = 0;
static void test_assert2(bool condition, const char* file, int line)
{
	if (condition) {
		total_passed++;
		printf("%s:%d test passed.\n", file, line);
		fflush(stdout);
		return;
	}
	printf("%s:%d test failed.\n", file, line);
	fflush(stdout);
	if (!condition) {
		abort();
	}
}
static void assert_dav_file_content(KWebDavClient* client, const char* path, const char* content, int content_length)
{
	KWebDavRequest* rq = nullptr;
	test_assert(KGL_OK == client->get(path, nullptr, &rq));
	char buf[512];
	test_assert(rq->read_all(buf, content_length+1)==content_length);
	test_assert(memcmp(buf, content, content_length) == 0);
	delete rq;
	return;
}
static void test_move_copy_lock(KWebDavClient* client, KWebDavClient* client2)
{
	printf("test_move_copy_lock\n");
#define COPY_LOCKED_SRC DAV_PREFIX_DIR "/copy-locked-src.txt"
	KStringBuf s;
	s << DAV_PREFIX_DIR "/lock-" << (int64_t)time(NULL) << "_" << __LINE__ << ".txt";
	test_assert(KGL_OK == client->lock(s.c_str()));
	KFixString in(kgl_expand_string(LOCKED_FILE_CONTENT));
	test_assert(KGL_OK == client2->put(COPY_LOCKED_SRC, &in));
	assert_dav_file_content(client2, COPY_LOCKED_SRC, kgl_expand_string(LOCKED_FILE_CONTENT));
	test_assert(KGL_OK != client2->copy(COPY_LOCKED_SRC, s.c_str(), true));
	client->unlock();
	test_assert(KGL_OK == client2->copy(COPY_LOCKED_SRC, s.c_str(), true));

	test_assert(KGL_OK == client->lock(s.c_str()));
	test_assert(KGL_OK != client2->copy(COPY_LOCKED_SRC, s.c_str(), true));
	test_assert(KGL_OK == client->copy(COPY_LOCKED_SRC, s.c_str(), true));
	assert_dav_file_content(client, s.c_str(), kgl_expand_string(LOCKED_FILE_CONTENT));
	client->unlock();
	client->_delete(s.c_str());


	test_assert(KGL_OK == client->lock(s.c_str()));
	test_assert(KGL_OK != client2->move(COPY_LOCKED_SRC, s.c_str()));
	test_assert(KGL_OK == client->move(COPY_LOCKED_SRC, s.c_str()));
	assert_dav_file_content(client, s.c_str(), kgl_expand_string(LOCKED_FILE_CONTENT));
	client->unlock();
	client->_delete(s.c_str());
}
static void test_lock(KWebDavClient* client, KWebDavClient* client2)
{
	printf("test_lock\n");
	KStringBuf s;
	s << DAV_PREFIX_DIR "/lock-" << (int64_t)time(NULL) << "_" << __LINE__ << ".txt";
	test_assert(KGL_OK == client->lock(s.c_str()));
	KFixString in(kgl_expand_string(LOCKED_FILE_CONTENT));
	KFixString in2(kgl_expand_string(LOCKED_FILE_CONTENT));
	test_assert(KGL_OK != client2->put(s.c_str(), &in));
	test_assert(KGL_OK == client->put(s.c_str(), &in2));
	assert_dav_file_content(client, s.c_str(), kgl_expand_string(LOCKED_FILE_CONTENT));
	assert_dav_file_content(client2, s.c_str(), kgl_expand_string(LOCKED_FILE_CONTENT));
	test_assert(KGL_OK == client->flush_lock());
	test_assert(KGL_OK != client2->_delete(s.c_str()));
	test_assert(KGL_OK != client->move(s.c_str(), DAV_PREFIX_DIR "/move-locked-failed.txt"));
	test_assert(KGL_OK != client2->move(s.c_str(), DAV_PREFIX_DIR "/move-locked-failed.txt"));
	test_assert(KGL_OK == client2->copy(s.c_str(), DAV_PREFIX_DIR "/copy-locked.txt", true));
	assert_dav_file_content(client, DAV_PREFIX_DIR "/copy-locked.txt", kgl_expand_string(LOCKED_FILE_CONTENT));
	test_assert(KGL_OK == client->unlock());
	test_assert(KGL_OK == client->_delete(s.c_str()));
	test_assert(KGL_OK == client->_delete(DAV_PREFIX_DIR "/copy-locked.txt"));

}
static bool is_file_exsit(const char* path, KWebDavClient* provider)
{
	KWebDavFileList file_list;
	auto result = provider->list(DAV_PREFIX_DIR "/", file_list);
	test_assert(result == KGL_OK);
	bool test_file_found = false;
	bool test_dir_found = false;
	for (auto it = file_list.files.begin(); it != file_list.files.end(); it++) {
		if ((*it)->is_directory) {
			if ((*it)->path == "dir") {
				test_dir_found = true;
			}
			printf("%s\t<DIR>\n", (*it)->path.c_str());
			continue;
		}
		if ((*it)->path == "test.txt") {
			test_file_found = true;
			test_assert((*it)->content_length == 4);
		}
		printf("%s\t" INT64_FORMAT "\n", (*it)->path.c_str(), (*it)->content_length);
	}
	return true;
}
static void clean_all_child(KWebDavClient* client, const char* path)
{
	printf("clean_all_child\n");
	KWebDavFileList file_list;
	test_assert(KGL_OK == client->list(path, file_list));
	for (auto it = file_list.files.begin(); it != file_list.files.end(); it++) {
		KStringBuf s;
		s << path << (*it)->path;
		if ((*it)->is_directory) {
			s << "/";
		}
		client->_delete(url_encode(s.c_str(),s.size()).c_str());
	}
}
static void test_get_range(KWebDavClient* client)
{
	printf("test_get_range\n");
	KFixString in2(kgl_expand_string("test"));
	test_assert(KGL_OK == client->put(DAV_PREFIX_DIR "/test.txt", &in2));
	assert_dav_file_content(client, DAV_PREFIX_DIR "/test.txt", kgl_expand_string("test"));
	KWebDavRequest* rq = nullptr;
	KRequestRange range;
	range.from = 1;
	range.to = 2;
	test_assert(KGL_OK == client->get(DAV_PREFIX_DIR "/test.txt", &range, &rq));
	test_assert(rq->resp.status_code == 206);
	char buf[512];
	test_assert(rq->read_all(buf, 3) == 2);
	test_assert(memcmp(buf, "es",2) == 0);
	delete rq;
	test_assert(client->_delete(DAV_PREFIX_DIR "/test.txt") == KGL_OK);
	return;
}
static int webdav_main(void* arg, int argc)
{
	char** argv = (char**)arg;
	if (argc < 2) {
		printf("Usage: %s test_webdav_url\n", argv[0]);
		return 1;
	}
	const char* host = nullptr;
	if (argc > 2) {
		host = argv[2];
	}
	selector_manager_set_timeout(5, 5);
	KWebDavClient provider, provider2;
	test_assert(provider.set_url(argv[1],host));
	test_assert(provider2.set_url(argv[1],host));
	provider.set_auth("test", "test");
	provider2.set_auth("test", "test");
	
	//return 0;
	//test_lock3(&provider, &provider2);
	//return 0;
	test_assert(KGL_OK == provider.option(DAV_PREFIX_DIR "/"));
	KWebDavFileList file_list;
	//clean
	clean_all_child(&provider, DAV_PREFIX_DIR "/");
	test_get_range(&provider);
	KFixString in(kgl_expand_string("ss"));
	test_assert(KGL_OK == provider.put(DAV_PREFIX_DIR "/test.txt", &in));
	//再次覆盖
	KFixString in2(kgl_expand_string("test"));
	test_assert(KGL_OK == provider.put(DAV_PREFIX_DIR "/test.txt", &in2));
	assert_dav_file_content(&provider, DAV_PREFIX_DIR "/test.txt", kgl_expand_string("test"));
	test_assert(KGL_OK == provider.mkcol(DAV_PREFIX_DIR "/dir/"));
	file_list.clean();
	test_assert(KGL_OK == provider.list(DAV_PREFIX_DIR "/", file_list));
	test_assert(file_list.find("dir") != nullptr);
	auto test_file = file_list.find("test.txt");
	test_assert(test_file != nullptr && test_file->content_length == 4);
	test_assert(KGL_OK == provider.move(DAV_PREFIX_DIR "/test.txt", DAV_PREFIX_DIR "/test2.txt"));
	test_assert(KGL_OK == provider.move(DAV_PREFIX_DIR "/dir/", DAV_PREFIX_DIR "/dir2/"));
	file_list.clean();
	test_assert(KGL_OK == provider.list(DAV_PREFIX_DIR "/", file_list));
	test_assert(file_list.find("dir") == nullptr);
	test_assert(file_list.find("test.txt") == nullptr);
	test_assert(file_list.find("dir2") != nullptr);
	test_assert(file_list.find("test2.txt") != nullptr);
	test_assert(KGL_OK == provider.copy(DAV_PREFIX_DIR "/test2.txt", DAV_PREFIX_DIR "/test_copyed.txt"));
	test_assert(KGL_EEXSIT == provider.copy(DAV_PREFIX_DIR "/test2.txt", DAV_PREFIX_DIR "/test_copyed.txt"));
	test_assert(KGL_OK == provider._delete(DAV_PREFIX_DIR "/dir2/"));
	test_assert(KGL_OK == provider._delete(DAV_PREFIX_DIR "/test2.txt"));
	//再次检测，看看能否成功删除。
	file_list.clean();
	test_assert(KGL_OK == provider.list(DAV_PREFIX_DIR "/", file_list));
	test_assert(file_list.find("dir") == nullptr);
	test_assert(file_list.find("test.txt") == nullptr);
	test_assert(file_list.find("test_copyed.txt") != nullptr && file_list.find("test_copyed.txt")->content_length == 4);
	test_assert(KGL_OK == provider._delete(DAV_PREFIX_DIR "/test_copyed.txt"));
	//test lock;
	test_lock(&provider, &provider2);
	test_move_copy_lock(&provider, &provider2);
	printf("total test passed=[%d]\n", total_passed);
	return 0;
}
int main(int argc, char** argv)
{
	return kasync_main(webdav_main, argv, argc);
}
