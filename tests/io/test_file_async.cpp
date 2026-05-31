// Copyright Danyil Melnytskyi 2025-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <coroutine/file.hpp>
#include <file.hpp>
#include <helpers.hpp>

#include <filesystem>
#include <string>

namespace ff = fast_task::file;

class FileAsyncTest : public SchedulerFixture {
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

TEST_F(FileAsyncTest, FutureWriteAndRead) {
    const std::string expected = "async file data";

    run_task([&] {
        auto f = ff::file_handle::open(tmp_path, ff::open_mode::read_write, ff::on_open_action::always_new);
        ASSERT_TRUE(f.is_open());

        f.fut_write(reinterpret_cast<const uint8_t*>(expected.data()),
                    static_cast<uint32_t>(expected.size()))
            ->get();

        f.seek_pos(0, ff::pointer_offset::begin);

        auto data = f.fut_read(static_cast<uint32_t>(expected.size()))->get();
        ASSERT_EQ(data.size(), expected.size());
        EXPECT_EQ(std::string(data.begin(), data.end()), expected);
    });
}

TEST_F(FileAsyncTest, FutureWriteAt) {
    run_task([&] {
        auto f = ff::file_handle::open(tmp_path, ff::open_mode::read_write, ff::on_open_action::always_new);
        ASSERT_TRUE(f.is_open());

        const uint8_t init[] = {'.', '.', '.', '.', 'X', '.', '.', '.', '.'};
        f.write(init, 9);

        const uint8_t patch = 'O';
        f.fut_write_at(4, &patch, 1)->get();

        uint8_t buf[9]{};
        f.read_at(0, buf, 9);
        EXPECT_EQ(buf[4], 'O');
        // surrounding bytes are unchanged
        EXPECT_EQ(buf[3], '.');
        EXPECT_EQ(buf[5], '.');
    });
}

TEST_F(FileAsyncTest, FutureReadAt) {
    run_task([&] {
        auto f = ff::file_handle::open(tmp_path, ff::open_mode::read_write, ff::on_open_action::always_new);
        ASSERT_TRUE(f.is_open());

        const uint8_t data[] = {'A', 'B', 'C', 'D', 'E'};
        f.write(data, 5);

        auto result = f.fut_read_at(2, 3)->get();
        ASSERT_EQ(result.size(), 3u);
        EXPECT_EQ(result[0], 'C');
        EXPECT_EQ(result[1], 'D');
        EXPECT_EQ(result[2], 'E');
    });
}

TEST_F(FileAsyncTest, FutureAppend) {
    run_task([&] {
        auto f = ff::file_handle::open(tmp_path, ff::open_mode::read_write, ff::on_open_action::always_new);
        ASSERT_TRUE(f.is_open());

        const uint8_t a[] = {'A', 'B'};
        f.fut_append(a, 2)->get();

        const uint8_t b[] = {'C', 'D'};
        f.fut_append(b, 2)->get();

        auto result = f.fut_read_at(0, 4)->get();
        ASSERT_EQ(result.size(), 4u);
        EXPECT_EQ(result[0], 'A');
        EXPECT_EQ(result[1], 'B');
        EXPECT_EQ(result[2], 'C');
        EXPECT_EQ(result[3], 'D');
    });
}

TEST_F(FileAsyncTest, AsyncWriteAndRead) {
    const std::string expected = "io_operation test";
    using namespace fast_task;
    auto test = [&] -> fast_task::task_coro<std::string> {
        auto f = ff::file_handle::open(tmp_path, ff::open_mode::read_write, ff::on_open_action::always_new);

        co_await async_write(f, reinterpret_cast<const uint8_t*>(expected.data()), static_cast<uint32_t>(expected.size()));
        f.seek_pos(0, ff::pointer_offset::begin);

        auto data = co_await async_read(f, expected.size());
        co_return std::string(data.begin(), data.end());
    };

    auto data = test().sync_get();
    ASSERT_EQ(data.size(), expected.size());
    EXPECT_EQ(data, expected);
}

TEST_F(FileAsyncTest, AsyncWriteAt) {
    using namespace fast_task;
    auto test = [&] -> fast_task::task_coro<std::vector<uint8_t>> {
        auto f = ff::file_handle::open(tmp_path, ff::open_mode::read_write, ff::on_open_action::always_new);

        const uint8_t zeros[8]{};
        co_await async_write(f, zeros, 8);

        const uint8_t val[] = {0xDE, 0xAD};
        co_await async_write_at(f, 3, val, 2);

        co_return co_await async_read_at(f, 3, 2);
    };

    auto data = test().sync_get();
    ASSERT_EQ(data.size(), 2u);
    EXPECT_EQ(data[0], 0xDE);
    EXPECT_EQ(data[1], 0xAD);
}

TEST_F(FileAsyncTest, SequentialFutureWrites) {
    run_task([&] {
        auto f = ff::file_handle::open(tmp_path, ff::open_mode::read_write, ff::on_open_action::always_new);
        ASSERT_TRUE(f.is_open());

        for (int i = 0; i < 4; ++i) {
            auto ch = static_cast<uint8_t>('A' + i);
            f.fut_write(&ch, 1)->get();
        }

        auto data = f.fut_read_at(0, 4)->get();
        ASSERT_EQ(data.size(), 4u);
        EXPECT_EQ(data[0], 'A');
        EXPECT_EQ(data[1], 'B');
        EXPECT_EQ(data[2], 'C');
        EXPECT_EQ(data[3], 'D');
    });
}
