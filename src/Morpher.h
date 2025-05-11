#pragma once

#include "shape.hpp"
#include "kd_matcher.hpp"

#include <vector>
#include <functional>
#include <unordered_set>

class BSGeometry;
class NiSkinPartition;
typedef uint64_t UInt64;
typedef uint32_t UInt32;
typedef uint16_t UInt16;
typedef uint8_t UInt8;
typedef int8_t SInt8;
inline RE::NiObject* NiRTTICast(RE::NiObject* obj, RE::NiRTTI* type) {
    if (obj->GetRTTI()->IsKindOf(type)) {
        return obj;
    }
    return nullptr;
}
#define ni_cast(obj, type) (RE::type*) NiRTTICast(obj.get(), (RE::NiRTTI*)RE::NiRTTI_##type.address())
class NormalApplicatorBackported {
    public:
        NormalApplicatorBackported(RE::NiPointer<RE::BSGeometry> _geometry, RE::NiPointer<RE::NiSkinPartition> _skinPartition);

        void Apply();

        void RecalcNormals(UInt32 numTriangles, Morpher::Triangle* triangles, const bool smooth = true, const float smoothThres = 60.0f);
        void CalcTangentSpace(UInt32 numTriangles, Morpher::Triangle* triangles);

    protected:
        RE::NiPointer<RE::BSGeometry> geometry;
        RE::NiPointer<RE::NiSkinPartition> skinPartition;
        std::unordered_set<UInt16> lockedVertices;
        std::vector<Morpher::Vector3> rawVertices;
        std::vector<Morpher::Vector3> rawNormals;
        std::vector<Morpher::Vector2> rawUV;
        std::vector<Morpher::Vector3> rawTangents;
        std::vector<Morpher::Vector3> rawBitangents;
};