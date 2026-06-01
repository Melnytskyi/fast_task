// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <file.hpp>
#include <helpers.hpp>

#include <filesystem>
#include <string>

namespace ff = fast_task::file;

class FileBasicTest : public SchedulerFixture {
protected:
    std::filesystem::path tmp_path;

    void SetUp() override {
        auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        tmp_path = std::filesystem::temp_directory_path() /
                   (std::string("ft_") + info->test_suite_name() + "_" + info->name());
        std::filesystem::remove(tmp_path);
    }

    void TearDown() override {
        std::filesystem::remove(tmp_path);
    }
};

TEST_F(FileBasicTest, OpenCreateAndClose) {
    run_task([&] {
        auto f = ff::file_handle::open(tmp_path, ff::open_mode::write, ff::on_open_action::always_new);
        EXPECT_TRUE(f.is_open());
        f.close();
        EXPECT_FALSE(f.is_open());
        EXPECT_TRUE(std::filesystem::exists(tmp_path));
    });
}

TEST_F(FileBasicTest, WriteAndRead) {
    const std::string expected = "Hello, fast_task file I/O!";

    run_task([&] {
        {
            auto f = ff::file_handle::open(tmp_path, ff::open_mode::write, ff::on_open_action::always_new);
            ASSERT_TRUE(f.is_open());
            f.write(reinterpret_cast<const uint8_t*>(expected.data()), static_cast<uint32_t>(expected.size()));
        }
        {
            auto f = ff::file_handle::open(tmp_path, ff::open_mode::read, ff::on_open_action::open_exists);
            ASSERT_TRUE(f.is_open());
            std::vector<uint8_t> buf(expected.size());
            uint32_t n = f.read(buf.data(), static_cast<uint32_t>(buf.size()));
            EXPECT_EQ(n, static_cast<uint32_t>(expected.size()));
            EXPECT_EQ(std::string(buf.begin(), buf.end()), expected);
        }
    });
}

TEST_F(FileBasicTest, WriteAtReadAt) {
    run_task([&] {
        {
            auto f = ff::file_handle::open(tmp_path, ff::open_mode::write, ff::on_open_action::always_new);
            ASSERT_TRUE(f.is_open());
            const uint8_t data[] = "ABCDEFGH";
            f.write(data, 8);
        }
        {
            auto f = ff::file_handle::open(tmp_path, ff::open_mode::read_write, ff::on_open_action::open_exists);
            ASSERT_TRUE(f.is_open());
            const uint8_t patch[] = {'X', 'Y'};
            f.write_at(2, patch, 2);

            uint8_t buf[4]{};
            uint32_t n = f.read_at(1, buf, 4);
            EXPECT_EQ(n, 4u);
            EXPECT_EQ(buf[0], 'B');
            EXPECT_EQ(buf[1], 'X');
            EXPECT_EQ(buf[2], 'Y');
            EXPECT_EQ(buf[3], 'E');
        }
    });
}

TEST_F(FileBasicTest, FileSize) {
    run_task([&] {
        auto f = ff::file_handle::open(tmp_path, ff::open_mode::write, ff::on_open_action::always_new);
        ASSERT_TRUE(f.is_open());
        const uint8_t data[16]{};
        f.write(data, 16);
        EXPECT_EQ(f.size(), 16);
    });
}

TEST_F(FileBasicTest, SeekAndRead) {
    run_task([&] {
        {
            auto f = ff::file_handle::open(tmp_path, ff::open_mode::write, ff::on_open_action::always_new);
            ASSERT_TRUE(f.is_open());
            const uint8_t data[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
            f.write(data, 10);
        }
        {
            auto f = ff::file_handle::open(tmp_path, ff::open_mode::read, ff::on_open_action::open_exists);
            ASSERT_TRUE(f.is_open());
            f.seek_pos(5, ff::pointer_offset::begin);
            uint8_t buf[5]{};
            uint32_t n = f.read(buf, 5);
            EXPECT_EQ(n, 5u);
            EXPECT_EQ(buf[0], '5');
            EXPECT_EQ(buf[4], '9');
        }
    });
}

TEST_F(FileBasicTest, AppendMode) {
    run_task([&] {
        {
            auto f = ff::file_handle::open(tmp_path, ff::open_mode::write, ff::on_open_action::always_new);
            ASSERT_TRUE(f.is_open());
            const uint8_t hello[] = {'H', 'e', 'l', 'l', 'o'};
            f.write(hello, 5);
        }
        {
            auto f = ff::file_handle::open(tmp_path, ff::open_mode::append, ff::on_open_action::open_exists);
            ASSERT_TRUE(f.is_open());
            const uint8_t world[] = {' ', 'W', 'o', 'r', 'l', 'd'};
            f.append(world, 6);
        }
        {
            auto f = ff::file_handle::open(tmp_path, ff::open_mode::read, ff::on_open_action::open_exists);
            ASSERT_TRUE(f.is_open());
            uint8_t buf[11]{};
            uint32_t n = f.read(buf, 11);
            EXPECT_EQ(n, 11u);
            EXPECT_EQ(std::string(reinterpret_cast<char*>(buf), 11), "Hello World");
        }
    });
}

TEST_F(FileBasicTest, GetPath) {
    run_task([&] {
        auto f = ff::file_handle::open(tmp_path, ff::open_mode::write, ff::on_open_action::always_new);
        ASSERT_TRUE(f.is_open());
        std::string path = f.get_path();
        EXPECT_FALSE(path.empty());
    });
}

TEST_F(FileBasicTest, FlushAndRead) {
    run_task([&] {
        auto f = ff::file_handle::open(tmp_path, ff::open_mode::read_write, ff::on_open_action::always_new);
        ASSERT_TRUE(f.is_open());
        const uint8_t data[] = {'A', 'B', 'C'};
        f.write(data, 3);
        f.flush();

        f.seek_pos(0, ff::pointer_offset::begin);
        uint8_t buf[3]{};
        uint32_t n = f.read(buf, 3);
        EXPECT_EQ(n, 3u);
        EXPECT_EQ(buf[0], 'A');
        EXPECT_EQ(buf[2], 'C');
    });
}
