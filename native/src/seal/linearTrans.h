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
            seal::Ciphertext v, std::vector<std::vector<double>> &M, int height, int width,
            seal::CKKSEncoder &ckks_encoder, const double &scale,
            seal::Encryptor &encryptor, seal::Evaluator &evaluator,
            seal::GaloisKeys &galois_keys, seal::RelinKeys &relin__keys)
    {
        seal::Ciphertext 
        int method = 0;
        if (height == width) method = 1; // square matrices
        else if (height < width) method = 2; // wide matrices
        else if (height > width) method = 3; // tall matrices

        int idx = 0;
        if (method == 1)
        {
            // squre matirces
            std::vector<std::vector<double>> tiledM = tillingMatrix(M, height, width);
            for (idx = 0; idx != height; ++idx)
            {
                seal::Ciphertext temp;
                evaluator.multiply_plain();
            }           


            return v;
        }
        else if (method == 2)
        {
            // wide matrices

            return v;
        }
        else if (method == 3)
        {
            // tall matrices

            return v;
        }
    }

} // namespace seal
