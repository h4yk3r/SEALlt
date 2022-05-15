// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/seal.h"
#include <map>
#include <stdexcept>
#include <vector>

namespace seal
{
    // tillingMatrix()
    // decompose and recontruct matrices
    inline std::vector<std::vector<double>> tillingMatrix(
            std::vector<std::vector<double>> raw_matrix,
            int height, int width)
    {
        std::vector<std::vector<double>> tiled_matrix;
        if (height >= width) // tall matrices & square matrices
        {
            for (int i = 0; i != width; ++i)
            {
                std::vector<double> temp;
                for (size_t j = 0; j != height; ++j)
                {
                    temp.push_back(raw_matrix[j % height][(i + j) % width]);
                }
                tiled_matrix.push_back(temp);
            }
        }
        else if (height < width) // wide matrices
        {
            for (int i = 0; i != height; ++i)
            {
                std::vector<double> temp;
                for (size_t j = 0; j != width; ++j)
                {
                    temp.push_back(raw_matrix[j % height][(i + j) % width]);
                }
                tiled_matrix.push_back(temp);
            }
        }
        return tiled_matrix;
    }

    // repeat-padding vectors
    // spread values
    inline std::vector<double> repeatpaddingVector(std::vector<double> raw_vector, int slot_count,
            int height, int width)
    {
        int stride = slot_count / height;
        int times = height / width;
        std::vector<double> temp(slot_count, 0);
        for (int i=0; i!=width; ++i)
            for (int j=0; j!=times; ++j)
                temp[(i + j * width) * stride] = raw_vector[i];
        return temp;
    }

    // padding vectors
    inline std::vector<double> paddingVector(std::vector<double> raw_vector, int slot_count)
    {
        int stride = slot_count / raw_vector.size();
        std::vector<double> temp(slot_count, 0);
        for (int i = 0; i != raw_vector.size(); ++i) temp[i * stride] = raw_vector[i];
        return temp;
    }

    // ntEncoding type A
    // do padding
    void ntEncoding(seal::CKKSEncoder &ckks_encoder, const double &scale,
            std::vector<double> &raw_vector, seal::Plaintext &destination,
            bool ifPadding = true)
    {
        if (ifPadding)
            ckks_encoder.encode(paddingVector(raw_vector, ckks_encoder.slot_count()), scale, destination);
        else ckks_encoder.encode(raw_vector, scale, destination);
    }

    // ntEncoding type B
    // do repeat padding
    void ntEncoding(seal::CKKSEncoder& ckks_encoder, const double& scale,
            std::vector<double>& raw_vector, seal::Plaintext& destination,
            int height, int width)
    {
        ckks_encoder.encode(repeatpaddingVector(raw_vector, ckks_encoder.slot_count(), height, width),
                scale, destination);
    }

    // main LT function
    seal::Ciphertext lt(
            int method;
            seal::Ciphertext v, std::vector<std::vector<double>> &M, int height, int width,
            seal::CKKSEncoder &ckks_encoder, const double &scale,
            seal::Encryptor &encryptor, seal::Evaluator &evaluator,
            seal::GaloisKeys &galois_keys, seal::RelinKeys &relin__keys)
    {
        seal::Ciphertext encryptedu = v;

        int idx = 0;
        if (method == 1 || method == 2) // decomposing matrix & hybrid
        {
            int stride = ckks_encoder.slot_count() / v.size();
            std::vector<seal::Ciphertext> rotedu(height);
            for (idx = 0; idx < height; ++idx)
			{
				evaluator.rotate_vector(encryptedu, idx * stride, galois_keys, rotedu[idx]);
			}
            std::vector<std::vector<double>> tiledM = tillingMatrix(M, height, width);
            std::vector<seal::Plaintext> encodedM;
			for (auto v : tiledM)
			{
				seal::Plaintext temp;
				ntEncoding(ckks_encoder, scale, v, temp);
				encodedM.push_back(temp);
			}
            seal::Ciphertext enc_result;
			evaluator.multiply_plain(rotedu[0], encodedM[0], enc_result);
			evaluator.relinearize_inplace(enc_result, relin_keys);
			evaluator.rescale_to_next_inplace(enc_result);
			for (idx = 1; idx < height; ++idx)
			{
				seal::Ciphertext temp;
				evaluator.multiply_plain(rotedu[idx], encodedM[idx], temp);
				evaluator.relinearize_inplace(temp, relin_keys);
				evaluator.rescale_to_next_inplace(temp);
				evaluator.add_inplace(enc_result, temp);
			}         
            if (method == 2) // additional R&S
			{
				int num = ckks_encoder.slot_count();
				while (num != height * stride)
				{
					Ciphertext temp;
					evaluator.rotate_vector(enc_result, num / 2, galois_keys, temp);
					evaluator.add_inplace(enc_result, temp);
					num /= 2;
				}
			}
            return enc_result;
        }
        else if (method == 3) // bsgs
        {
            // BSGS parameters
			int max_len = std::max(height, width);
			int min_len = std::min(height, width);
			double n_ddot = (double)min_len;
			int g_tilde = (int)ceil(sqrt(n_ddot));
			int b_tilde = (int)ceil(n_ddot / g_tilde);
			// preprocessing matrix
			std::vector<seal::Plaintext> encodedM(min_len);
			std::vector<std::vector<double>> tiledM = tilingMatrix(M, height, width);
			for (int b = 0; b < b_tilde; ++b)
			{
				for (int g = 0; g < g_tilde && b * g_tilde + g < min_len; ++g)
				{
					std::vector<double>& temp = tiledM[b * g_tilde + g];
					std::rotate(temp.rbegin(), temp.rbegin() + b * g_tilde, temp.rend());
					Plaintext coded_temp;
					ntEncoding(ckks_encoder, scale, temp, coded_temp);
					encodedM[b * g_tilde + g] = coded_temp;
				}
			}
			encodedM.shrink_to_fit();
			// rotate ciphertext
			vector<seal::Ciphertext> rotedu(g_tilde);
			rotedu[0] = encryptedu;
			for (idx = 1; idx < g_tilde; ++idx)
			{
				evaluator.rotate_vector(encryptedu, idx * stride, galois_keys, rotedu[idx]);
			}
			// evaluate
			Ciphertext res;
			int g, b;
			// b=0, g=0
			evaluator.multiply_plain(rotedu[0], encodedM[0], res);
			evaluator.relinearize_inplace(res, relin_keys);
			evaluator.rescale_to_next_inplace(res);
			// b=0, g>=1
			for (g = 1; g < g_tilde; ++g)
			{
				Ciphertext temp = rotedu[g];
				evaluator.multiply_plain_inplace(temp, encodedM[g]);
				evaluator.relinearize_inplace(temp, relin_keys);
				evaluator.rescale_to_next_inplace(temp);
				evaluator.add_inplace(res, temp);
			}
			//b>=1
			for (b = 1; b < b_tilde; ++b)
			{
				Ciphertext temp_res;
				for (size_t g = 0; g != g_tilde && b * g_tilde + g != min_len; ++g)
				{
					Ciphertext temp = rotedu[g];
					evaluator.multiply_plain_inplace(temp, encodedM[b * g_tilde + g]);
					evaluator.relinearize_inplace(temp, relin_keys);
					evaluator.rescale_to_next_inplace(temp);
					if (g == 0) temp_res = temp;
					else evaluator.add_inplace(temp_res, temp);
				}
				evaluator.rotate_vector_inplace(temp_res, b * g_tilde * stride, galois_keys);
				evaluator.add_inplace(res, temp_res);
			}
			if (height < width) // additional R&S
			{
				int num = width / height;
				while (num != 1)
				{
					Ciphertext temp = res;
					evaluator.rotate_vector_inplace(res, height * num * stride / 2, galois_keys);
					evaluator.add_inplace(res, temp);
					num /= 2;
				}
			}
            return res;
        }
    }

} // namespace seal
