#pragma once
#include <filesystem>

namespace fs = std::filesystem;

class File;
class Directory;

static class FileSystem {
public:
	static std::vector<File> getFilesInDirectory(std::string path);
	static std::vector<Directory> getDirectoriesInDirectory(std::string path, bool recursive);
	static std::vector<Directory> getDirectoriesInDirectory(std::string path);
};

class File {

public:

	fs::path path;

	std::string contents;

	FILE* fp;

	File(std::string path_) {

		path = fs::path(path_);
		fopen_s(&fp, path.generic_string().c_str(), "r");

		if (fp != 0) {
			char buffer[128];
			while (fgets(buffer, sizeof(buffer), fp) != nullptr) { contents += buffer; }
		}

	}

	~File() {
		if (fp != 0)
			fclose(fp);
	}

};

class Directory {

public:

	fs::path path;

	std::vector<Directory> directories;
	std::vector<File> files;

	Directory(std::string path_, bool recursive) {
		path = fs::path(path_);
		files = FileSystem::getFilesInDirectory(path.generic_string());

		if (recursive)
			directories = FileSystem::getDirectoriesInDirectory(path.generic_string(), recursive);
	}

	Directory(std::string path_) {
		path = fs::path(path_);
		files = FileSystem::getFilesInDirectory(path.generic_string());

		directories = FileSystem::getDirectoriesInDirectory(path.generic_string(), false);
	}

	std::string toString(int indents) {

		std::string r = "";
		
		for (int i = 0; i < indents; i++)
			r += "  ";

		r += this->path.filename().generic_string() + "/\n";

		for (File file : this->files) {

			for (int i = 0; i < indents + 1; i++)
				r += "  ";

			r += file.path.filename().generic_string() + '\n';
		}

		for (Directory directory : this->directories) {
			r += directory.toString(indents+1);
		}

		r += '\n';

		return r;
	}

	std::string toString() {

		std::string r = this->path.generic_string()+"/\n";

		for (File file : this->files) {
			r += '\t' + file.path.generic_string() + '\n';
		}

		for (Directory directory : this->directories) {
			r += directory.toString(1);
		}

		r += '\n';

		return r;
	}

};

std::vector<File> FileSystem::getFilesInDirectory(std::string path) {

	std::vector<File> files;

	if (!fs::directory_entry(fs::path(path)).is_directory())
		return files;

	for (auto const& entry : fs::directory_iterator(path)) {
		if (entry.is_regular_file()) {
			try {
				files.push_back(File(entry.path().generic_string()));
			} catch (const std::system_error& e) {
				; // Eventually maybe report back to the C2 server
			}
		}
	}

	return files;
}

std::vector<Directory> FileSystem::getDirectoriesInDirectory(std::string path, bool recursive) {

	std::vector<Directory> directories;

	if (!fs::directory_entry(fs::path(path)).is_directory())
		return directories;

	for (auto const& entry : fs::directory_iterator(path)) {
		if (!entry.is_regular_file() && entry.is_directory()) {
			try {
				directories.push_back(Directory(entry.path().generic_string(), recursive));
			}
			catch (const std::system_error & e) { 
				; // Eventually maybe report back to the C2 server
			}
		}
	}

	return directories;
}

std::vector<Directory> FileSystem::getDirectoriesInDirectory(std::string path) {

	std::vector<Directory> directories;

	if (!fs::directory_entry(fs::path(path)).is_directory())
		return directories;

	for (auto const& entry : fs::directory_iterator(path)) {
		if (!entry.is_regular_file() && entry.is_directory()) {
			try {
				directories.push_back(Directory(entry.path().generic_string(), false));
			} catch (const std::system_error& e) {
				; // Eventually maybe report back to the C2 server
			}
		}
	}

	return directories;
}