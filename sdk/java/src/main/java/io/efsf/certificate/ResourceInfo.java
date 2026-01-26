package io.efsf.certificate;

import java.util.Map;
import java.util.Objects;

/**
 * Information about a destroyed resource.
 */
public final class ResourceInfo {

    private final String resourceType;
    private final String resourceId;
    private final long sizeBytes;
    private final String location;

    public ResourceInfo(String resourceType, String resourceId, long sizeBytes, String location) {
        this.resourceType = Objects.requireNonNull(resourceType);
        this.resourceId = Objects.requireNonNull(resourceId);
        this.sizeBytes = sizeBytes;
        this.location = location;
    }

    public ResourceInfo(String resourceType, String resourceId, long sizeBytes) {
        this(resourceType, resourceId, sizeBytes, null);
    }

    public String getResourceType() {
        return resourceType;
    }

    public String getResourceId() {
        return resourceId;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public String getLocation() {
        return location;
    }

    public Map<String, Object> toMap() {
        if (location != null) {
            return Map.of(
                "resource_type", resourceType,
                "resource_id", resourceId,
                "size_bytes", sizeBytes,
                "location", location
            );
        }
        return Map.of(
            "resource_type", resourceType,
            "resource_id", resourceId,
            "size_bytes", sizeBytes
        );
    }

    public static ResourceInfo fromMap(Map<String, Object> map) {
        return new ResourceInfo(
            (String) map.get("resource_type"),
            (String) map.get("resource_id"),
            ((Number) map.get("size_bytes")).longValue(),
            (String) map.get("location")
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ResourceInfo that = (ResourceInfo) o;
        return sizeBytes == that.sizeBytes &&
            Objects.equals(resourceType, that.resourceType) &&
            Objects.equals(resourceId, that.resourceId) &&
            Objects.equals(location, that.location);
    }

    @Override
    public int hashCode() {
        return Objects.hash(resourceType, resourceId, sizeBytes, location);
    }

    @Override
    public String toString() {
        return "ResourceInfo{" +
            "resourceType='" + resourceType + '\'' +
            ", resourceId='" + resourceId + '\'' +
            ", sizeBytes=" + sizeBytes +
            ", location='" + location + '\'' +
            '}';
    }
}
